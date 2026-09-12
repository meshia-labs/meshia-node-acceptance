"""Download only the immutable public wheel and bind installed import evidence."""
import hashlib
import ctypes
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import sys
import urllib.request
import zipfile

NAME = "meshia_node-1.3.38-py3-none-any.whl"
PUBLIC_SHA = "6a570e0cd2b5f034861a051f7db454ee3249fe6e71a4cc51112389f1da6e7fe6"
SOURCE = "1084de4e5011b04dd4f5fffd26b3f87692686da0"
directory = Path("windows37-evidence")
directory.mkdir(exist_ok=True)
if sys.argv[1] == "download":
    with urllib.request.urlopen("https://meshia.io/meshia-node/" + NAME, timeout=30) as response:
        data = response.read(20 * 1024 * 1024 + 1)
    assert len(data) <= 20 * 1024 * 1024
    assert hashlib.sha256(data).hexdigest() == PUBLIC_SHA
    (directory / NAME).write_bytes(data)
elif sys.argv[1] == "verify":
    import meshia_node
    from meshia_node.workspace import WorkspaceBoundary
    from meshia_node.winsec import current_user_sid, is_owner_restricted, ensure_owner_restricted
    assert sys.platform == "win32"
    assert not hasattr(os, "pread"), "Windows must exercise portable seek/read"
    assert importlib.metadata.version("meshia-node") == "1.3.38"
    assert "site-packages" in str(Path(meshia_node.__file__).resolve())
    assert "workspace_win" in WorkspaceBoundary.__module__
    assert not ctypes.windll.shell32.IsUserAnAdmin(), "Qualification requires an ordinary user"
    state = Path(os.environ["TEMP"]) / "owner-proof"
    state.mkdir()
    ensure_owner_restricted(state)
    assert is_owner_restricted(state), "Actual owner must match the current ordinary SID"
    assert hashlib.sha256((directory / NAME).read_bytes()).hexdigest() == PUBLIC_SHA
    with zipfile.ZipFile(directory / NAME) as wheel:
        modules = [name for name in wheel.namelist() if name.startswith("meshia_node/") and name.endswith(".py")]
        assert len(modules) > 3
        for module in modules:
            assert (Path(meshia_node.__file__).parent.parent / module).read_bytes() == wheel.read(module)
    (directory / "installed.json").write_text(json.dumps({
        "schema": "meshia.windows_descriptor_qualification.v1", "package": NAME,
        "qualification_artifact": "public",
        "sha256": PUBLIC_SHA, "source_commit": SOURCE, "platform": platform.platform(),
        "python": platform.python_version(), "workspace_boundary": WorkspaceBoundary.__module__,
        "portable_pread": True, "paired": False, "mount_started": False,
        "installed_modules_verified": len(modules),
        "current_sid": current_user_sid(), "state_owner_matches_current_sid": True, "admin": False,
    }, indent=2) + "\n", encoding="utf-8")
else:
    raise SystemExit("unknown operation")
