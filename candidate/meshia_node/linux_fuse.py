"""Linux libfuse2 request context and local-only open-inode aliases.

Linux fstat can send GETATTR without a file handle. libfuse must retain its
hidden inode name for that request, but those names must never enter Fabric.
The original request opcode distinguishes unlink from replacement retirement.
"""
from __future__ import annotations

import ctypes
from concurrent.futures import ThreadPoolExecutor
import errno
from functools import partial
import os
import re
import select
import struct
import threading
from typing import Any

_UNLINK = 10
_RENAME = 12
_RENAME2 = 45
_HIDDEN = re.compile(r"\.fuse_hidden[0-9a-f]{16}\Z")


class LinuxInodeOperations:
    def __init__(self, operations: Any) -> None:
        self.operations = operations
        self.context = threading.local()
        self._lock = threading.RLock()
        self._paths: dict[int, str] = {}
        self._aliases: dict[str, set[int]] = {}
        self._failed_retirements: dict[str, str] = {}

    def __getattr__(self, name: str) -> Any:
        return getattr(self.operations, name)

    def __call__(self, name: str, *args: Any) -> Any:
        return getattr(self, name)(*args)

    def process(self, buffer: bytes, callback: Any) -> None:
        # fuse_in_header is a stable 40-byte kernel ABI; rename body begins
        # with newdir (plus flags/padding for RENAME2), then two NUL names.
        if len(buffer) < 40 or struct.unpack_from("=I", buffer)[0] != len(buffer):
            raise ValueError("Invalid FUSE request framing")
        opcode = struct.unpack_from("=I", buffer, 4)[0]
        target = None
        if opcode in (_RENAME, _RENAME2):
            names = buffer[56 if opcode == _RENAME2 else 48:].split(b"\0")
            if len(names) >= 3:
                target = os.fsdecode(names[1])
        self.context.request = (opcode, target)
        self.context.retirements = []
        try:
            callback()
        finally:
            del self.context.request
            del self.context.retirements

    def open(self, path: str, flags: int) -> int:
        with self._lock:
            if path in self._aliases:
                # If the user rename failed after libfuse hid its destination,
                # an already-cached public dentry still names that inode. OPEN
                # carries no path on the wire; route it to the unchanged public
                # name. LOOKUP cannot discover the hidden alias itself.
                opcode, _ = getattr(self.context, "request", (None, None))
                public = self._failed_retirements.get(path) if opcode == 14 else None
                if public is None:
                    raise self.operations.fuse_error(errno.ENOENT)
            else:
                public = path
        handle = self.operations.open(public, flags)
        with self._lock:
            self._paths[handle] = path
            if path in self._aliases:
                self._aliases[path].add(handle)
        return handle

    def create(self, path: str, mode: int, fi: Any = None) -> int:
        handle = self.operations.create(path, mode, fi)
        with self._lock:
            self._paths[handle] = path
        return handle

    def getattr(self, path: str | None, fh: int | None = None) -> Any:
        with self._lock:
            handles = self._aliases.get(path) if path is not None else None
            handle = next(iter(handles), None) if handles is not None else None
        if handles is not None:
            opcode, _ = getattr(self.context, "request", (None, None))
            if opcode == 1:  # Never make a hidden alias discoverable by LOOKUP.
                raise self.operations.fuse_error(errno.ENOENT)
            if handle is None:
                raise self.operations.fuse_error(errno.ENOENT)
            attrs = dict(self.operations.getattr(None, handle))
            # libfuse decrements a positive link count on its hidden inode.
            # A failed replacement still has one real public link; compensate
            # only at this private callback boundary so kernel fstat sees one.
            with self._lock:
                attrs["st_nlink"] = 2 if path in self._failed_retirements else 0
            return attrs
        return self.operations.getattr(path, fh)

    def rename(self, old: str, new: str) -> Any:
        opcode, target = getattr(self.context, "request", (None, None))
        name = new.rsplit("/", 1)[-1]
        internal = bool(_HIDDEN.fullmatch(name)) and (
            opcode == _UNLINK or opcode in (_RENAME, _RENAME2) and name != target)
        with self._lock:
            handles = {handle for handle, path in self._paths.items() if path == old}
        if internal:
            if not handles:
                raise self.operations.fuse_error(errno.EBUSY)
            if opcode == _UNLINK:
                # Delete the public name once, retaining bytes through the
                # backend's normal anonymous handle lifetime.
                self.operations.unlink(old)
            # A replacement's final rename performs the one atomic Fabric CAS.
            # Its preceding destination hide must not enqueue a DELETE.
            with self._lock:
                self._aliases[new] = handles.intersection(self._paths)
                for handle in self._aliases[new]:
                    self._paths[handle] = new
            if opcode in (_RENAME, _RENAME2):
                self.context.retirements.append((old, new))
            return 0
        try:
            result = self.operations.rename(old, new)
        except BaseException:
            with self._lock:
                for public, hidden in getattr(self.context, "retirements", []):
                    if public == new and hidden in self._aliases:
                        self._failed_retirements[hidden] = public
            raise
        with self._lock:
            if old != new:
                for hidden, public in list(self._failed_retirements.items()):
                    if public == new:
                        del self._failed_retirements[hidden]
                    elif public == old:
                        self._failed_retirements[hidden] = new
            for handle, path in list(self._paths.items()):
                if path == old:
                    self._paths[handle] = new
        return result

    def unlink(self, path: str) -> Any:
        with self._lock:
            if path in self._aliases:
                opcode, _ = getattr(self.context, "request", (None, None))
                if opcode == _UNLINK:
                    raise self.operations.fuse_error(errno.ENOENT)
                del self._aliases[path]
                self._failed_retirements.pop(path, None)
                return 0
        result = self.operations.unlink(path)
        with self._lock:
            for hidden, public in list(self._failed_retirements.items()):
                if public == path:
                    del self._failed_retirements[hidden]
        return result

    def release(self, path: str | None, fh: int) -> Any:
        try:
            return self.operations.release(path, fh)
        finally:
            with self._lock:
                self._paths.pop(fh, None)
                for handles in self._aliases.values():
                    handles.discard(fh)

    def clear(self) -> None:
        with self._lock:
            self._aliases.clear()
            self._paths.clear()
            self._failed_retirements.clear()


def run_linux_fuse(module: Any, operations: Any, mountpoint: str, **options: Any) -> None:
    """Use fusepy callbacks with a bounded public-libfuse request loop."""
    owner = LinuxInodeOperations(operations)
    adapter = module.FUSE.__new__(module.FUSE)
    adapter.operations = owner
    adapter.raw_fi = False
    adapter.encoding = "utf-8"
    adapter.use_ns = getattr(owner, "use_ns", False)
    adapter._FUSE__critical_exception = None
    args = ["fuse"]
    args.extend(flag for key, flag in adapter.OPTIONS if options.pop(key, False))
    args += ["-o", ",".join(adapter._normalize_fuse_options(**options)), mountpoint]
    argv = (ctypes.c_char_p * len(args))(*(item.encode() for item in args))
    callbacks = module.fuse_operations()
    for item in module.fuse_operations._fields_:
        name, prototype = item[:2]
        check = name[1:] if name in ("fgetattr", "ftruncate") else name
        value = getattr(owner, check, None)
        if value is not None:
            if hasattr(prototype, "argtypes"):
                value = prototype(partial(adapter._wrapper, getattr(adapter, name)))
            setattr(callbacks, name, value)

    library = module._libfuse
    pointer = ctypes.c_void_p
    signatures = {
        "fuse_setup": ([ctypes.c_int, ctypes.POINTER(ctypes.c_char_p), pointer,
                        ctypes.c_size_t, ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_int), pointer], pointer),
        "fuse_get_session": ([pointer], pointer),
        "fuse_session_next_chan": ([pointer, pointer], pointer),
        "fuse_chan_fd": ([pointer], ctypes.c_int),
        "fuse_chan_bufsize": ([pointer], ctypes.c_size_t),
        "fuse_chan_recv": ([ctypes.POINTER(pointer), pointer, ctypes.c_size_t], ctypes.c_int),
        "fuse_session_process": ([pointer, pointer, ctypes.c_size_t, pointer], None),
        "fuse_session_exit": ([pointer], None),
        "fuse_session_exited": ([pointer], ctypes.c_int),
        "fuse_teardown": ([pointer, ctypes.c_char_p], None),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
    native_mount = ctypes.c_char_p()
    multithreaded = ctypes.c_int()
    fuse = library.fuse_setup(len(args), argv, ctypes.byref(callbacks), ctypes.sizeof(callbacks),
                              ctypes.byref(native_mount), ctypes.byref(multithreaded), None)
    if not fuse:
        raise RuntimeError("Linux FUSE setup failed")
    failures: list[BaseException] = []
    slots = threading.BoundedSemaphore(8)
    try:
        session = library.fuse_get_session(fuse)
        channel = pointer(library.fuse_session_next_chan(session, None))
        if not session or not channel.value:
            raise RuntimeError("Linux FUSE request session unavailable")
        capacity = library.fuse_chan_bufsize(channel)
        if not 40 <= capacity <= 16 * 1024 * 1024:
            raise RuntimeError("Linux FUSE request capacity invalid")
        poller = select.poll()
        poller.register(library.fuse_chan_fd(channel), select.POLLIN | select.POLLERR | select.POLLHUP)

        def process(body: bytes, current_channel: int) -> None:
            try:
                buffer = ctypes.create_string_buffer(body)
                owner.process(body, lambda: library.fuse_session_process(
                    session, buffer, len(body), current_channel))
            except BaseException as error:
                failures.append(error)
                library.fuse_session_exit(session)
            finally:
                slots.release()

        with ThreadPoolExecutor(max_workers=8, thread_name_prefix="meshia-fuse") as workers:
            buffer = ctypes.create_string_buffer(capacity)
            while not library.fuse_session_exited(session):
                # Polling bounds shutdown even when no new kernel request
                # arrives after a callback failure; it never retries a syscall.
                if not poller.poll(100):
                    continue
                if not slots.acquire(timeout=.1):
                    continue
                received = library.fuse_chan_recv(ctypes.byref(channel), buffer, capacity)
                if received <= 0:
                    slots.release()
                    if received in (-errno.EINTR, -errno.EAGAIN):
                        continue
                    if received not in (0, -errno.ENODEV):
                        raise OSError(-received, "Linux FUSE receive failed")
                    break
                try:
                    workers.submit(process, buffer.raw[:received], channel.value)
                except BaseException:
                    slots.release()
                    raise
        if failures:
            raise failures[0]
        if adapter._FUSE__critical_exception:
            raise adapter._FUSE__critical_exception
    finally:
        library.fuse_teardown(fuse, native_mount)
        owner.clear()
