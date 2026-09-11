"""Native owner grants for disposable OS acceptance accounts.

Keep the legacy protocol fixture available to its existing consumers. Native
lifecycle proofs need production's unique active host/session attachment and
owner-controlled permissions, including across installer upgrades (M445/M1841).
"""
from typing import Any
from datetime import datetime, timezone
import threading
import uuid
from fixture_v2 import FabricV2Fixture

from fixture_control_plane import (
    ACCEPTED_PROFILES, FakeControlPlane, Host, NATIVE_FULL_PROFILE, NATIVE_WORKSPACE_PROFILE,
    PERSONAL_PROFILE, Rejected,
)


class NativeAcceptancePlane(FakeControlPlane):
    def select_access_mode(self, mode: str) -> None:
        """Simulate the authenticated owner's permission update, not a node hint."""
        if mode not in ("files", "limited", "full"):
            raise ValueError(mode)
        with self._state_lock:
            self.access_mode = mode
            profile = {"files": PERSONAL_PROFILE, "limited": NATIVE_WORKSPACE_PROFILE,
                       "full": NATIVE_FULL_PROFILE}[mode]
            for attachment in self.attachments.values():
                host = self.hosts.get(attachment.get("host_id"))
                if host and attachment.get("session_id") == host.session_id:
                    attachment["permissions"] = dict(profile)

    def attach(self, host: Host, payload: dict[str, Any]):
        with self._state_lock:
            if payload.get("permissions") not in ACCEPTED_PROFILES:
                raise Rejected(400, "PERMISSION_PROFILE_INVALID")
            existing = next((item for item in self.attachments.values()
                if item.get("host_id") == host.id
                and item.get("host_generation") == host.generation
                and item.get("session_id") == host.session_id
                and item.get("status") == "active"), None)
            if existing is None:
                profile = {"full": NATIVE_FULL_PROFILE,
                           "limited": NATIVE_WORKSPACE_PROFILE}.get(
                               self.access_mode, PERSONAL_PROFILE)
                return super().attach(host, dict(payload, permissions=dict(profile)))
            if (payload.get("session_id") != host.session_id
                    or payload.get("mount_name") != existing["mount_name"]):
                raise Rejected(409, "ATTACHMENT_CONFLICT")
            # M1841 validates the profile shape, then replaces the node's hint
            # with durable owner authority before calling M445. Reconnecting
            # before the next heartbeat must preserve that owner choice.
            existing["lease_expires_at"] = self.now() + 90
            host.status = "connected"
            grant = self._object_edge_document(host.session_id, existing["id"])
            return 201, {
                "attachment": existing, "reused": True,
                "workspace_name": self.workspace_name,
                "account_id": host.owner_id, "account_email": host.owner_email,
                **({"object_edge": grant} if grant is not None else {}),
            }

    def attach_workspaces(self, host: Host, payload: dict[str, Any]):
        with self._state_lock:
            # A stale node hint cannot change a grant already chosen by the owner.
            profiles = {key: dict(item["permissions"])
                        for key, item in self.attachments.items()}
            status, document = super().attach_workspaces(host, payload)
            for receipt in document["attachments"]:
                attachment = self.attachments[receipt["attachment"]["id"]]
                primary = attachment["session_id"] == host.session_id
                profile = profiles.get(attachment["id"])
                if profile is None:
                    profile = ({"full": NATIVE_FULL_PROFILE,
                                "limited": NATIVE_WORKSPACE_PROFILE}.get(
                                    self.access_mode, PERSONAL_PROFILE)
                               if primary else PERSONAL_PROFILE)
                attachment["permissions"] = dict(profile)
            return status, document

    def heartbeat_workspaces(self, host: Host, payload: dict[str, Any]):
        with self._state_lock:
            status, document = super().heartbeat_workspaces(host, payload)
            for receipt in document["attachments"]:
                profile = self.attachments[receipt["attachment_id"]]["permissions"]
                receipt["access_mode"] = (
                    "full" if profile == NATIVE_FULL_PROFILE else
                    "limited" if profile == NATIVE_WORKSPACE_PROFILE else "files")
            return status, document

    def claim(self, host: Host):
        with self._state_lock:
            return super().claim(host)

    def _transition(self, host: Host, status: str) -> None:
        # transition_connected_host_273 fences the old generation as one
        # transaction. Retain revoked device history rather than deleting it.
        with self._state_lock:
            if host.status == "revoked" or (status == "disconnected" and host.status != "connected"):
                raise Rejected(409, "HOST_TRANSITION_CONFLICT")
            for attachment in self.attachments.values():
                if (attachment.get("host_id") == host.id
                        and attachment.get("host_generation") == host.generation
                        and attachment.get("status") == "active"):
                    attachment["status"] = status
                    attachment["lease_expires_at"] = None
            # Each disposable acceptance account has one host and queue.
            for command in self.commands:
                if command.status in ("queued", "claimed"):
                    command.status = "canceled"
                    command.claim_token = None
            host.status = status
            host.generation += 1

    def disconnect(self, host: Host):
        self._transition(host, "disconnected")
        return 200, {"disconnected": True, "generation": host.generation}

    def revoke(self, host: Host) -> None:
        self._transition(host, "revoked")

    def forget(self, host: Host):
        self.revoke(host)
        return 200, {"forgotten": True}


class AcceptancePlane(FabricV2Fixture, NativeAcceptancePlane):
    """Current native claim receipts over the shared authenticated fixture."""

    def __init__(self) -> None:
        super().__init__()
        self.access_mode = "full"
        self.completions: dict[str, dict[str, Any]] = {}
        self.cancelled: set[str] = set()
        self.app_access_revision = 1
        self.app_grants: dict[str, dict[str, Any]] = {}

    def select_access_mode(self, mode: str) -> None:
        previous = self.access_mode
        super().select_access_mode(mode)
        if mode != previous:
            self.app_access_revision += 1

    def claim_apps(self, host: Host, payload: dict[str, Any]):
        """The remote grant is a fixture; installed native ownership is not."""
        with self._state_lock:
            attachment = next((item for item in self.attachments.values()
                if item.get('host_id') == host.id and item.get('host_generation') == host.generation
                and item.get('session_id') == host.session_id and item.get('status') == 'active'), None)
            allowed = host.status == 'connected' and attachment is not None and self.access_mode in ('full', 'limited')
            common = {'host_generation': host.generation,
                      'attachment_id': attachment['id'] if attachment else None,
                      'attachment_connection_generation': 1, 'access_revision': self.app_access_revision}
            supervision = []
            active_fields = {'session_id', 'attachment_id', 'attachment_connection_generation',
                             'access_revision', 'app_id', 'instance_id'}
            for active in payload.get('active_apps', []):
                if (not isinstance(active, dict) or set(active) != active_fields
                        or not isinstance(active.get('app_id'), str) or not 1 <= len(active['app_id']) <= 64):
                    raise Rejected(400, 'APP_SUPERVISION_INVALID')
                grant = self.app_grants.get(active['app_id'])
                exact = bool(allowed and grant and grant['host_id'] == host.id
                    and grant['deadline'] > self.now() and grant['mode'] == self.access_mode
                    and grant['common'] == common and active['session_id'] == host.session_id
                    and all(active[key] == common[key] for key in active_fields & common.keys())
                    and isinstance(active['instance_id'], str))
                try:
                    exact = exact and str(uuid.UUID(active['instance_id'])) == active['instance_id']
                except (ValueError, TypeError, AttributeError):
                    exact = False
                if exact and grant['instance_id'] is None:
                    grant['instance_id'] = active['instance_id']
                exact = exact and active['instance_id'] == grant['instance_id']
                supervision.append({**active, 'continue': bool(exact),
                                    **({'supervision_seconds': 15} if exact else {})})
            commands = []
            if allowed:
                _, claimed = FakeControlPlane.claim(self, host, app_lane=True)
                if claimed is not None:
                    command = claimed['command']
                    command.update(common, execution_scope='host' if self.access_mode == 'full' else 'workspace',
                        expires_at=datetime.fromtimestamp(self.now() + 30, timezone.utc).isoformat())
                    command['payload'] = {**command['payload'], **common,
                        'schema': 'meshia.connected_host_' + command['command_type'] + '.v1'}
                    if command['command_type'] == 'app_control' and command['payload'].get('operation') == 'register_lab_app':
                        name = command['payload']['arguments']['app_id']
                        self.app_grants[name] = {'host_id': host.id, 'common': common, 'mode': self.access_mode,
                                                'deadline': self.now() + 90, 'instance_id': None}
                    commands.append(command)
            return 200, {'commands': commands, 'app_supervision': supervision}

    def claim(self, host: Host):
        status, document = super().claim(host)
        if document is not None:
            document["command"]["execution_scope"] = (
                "workspace" if self.access_mode == "limited" else "host"
            )
        return status, document

    def supervise(self, host: Host, active: dict[str, Any]):
        command = next((item for item in self.commands if item.id == active.get("id")), None)
        allowed = bool(
            command and command.id not in self.cancelled
            and command.claim_token == active.get("claim_token")
            and command.status == "claimed" and self.access_mode in ("limited", "full")
            and host.status == "connected"
        )
        return 200, {"supervision": {"continue": allowed,
            **({"supervision_seconds": 15} if allowed else {})}}

    def complete(self, host: Host, command_id: str, payload: dict[str, Any]):
        with self._state_lock:
            result = super().complete(host, command_id, payload)
            self.completions[command_id] = payload
            command = self.completed[command_id]
            if command.command_type == 'app_control':
                operation = command.payload.get('operation')
                if ((operation == 'unregister_lab_app' and payload.get('status') == 'succeeded')
                        or (operation == 'register_lab_app' and payload.get('status') != 'succeeded')):
                    self.app_grants.pop(command.payload.get('arguments', {}).get('app_id'), None)
            return result


class AccessTransitionPlane(AcceptancePlane):
    """Hold the prior heartbeat access snapshot while signed claims advance.

    Every heartbeat completes normally, leaving the client's shared signing
    lock free. This deterministic fixture ordering is not a production network
    race. Authentication, claim authority, leases and supervision are unchanged.
    """

    def __init__(self):
        super().__init__()
        self.heartbeat_observed = threading.Event()
        self._heartbeat_access = None
        self._heartbeat_access_deadline = None

    def begin_access_transition(self, mode):
        with self._state_lock:
            if mode == self.access_mode or self._heartbeat_access is not None:
                raise AssertionError('Access transition fixture state changed')
            self.heartbeat_observed.clear()
            self._heartbeat_access = self.access_mode
            self._heartbeat_access_deadline = self.now() + 45
            self.select_access_mode(mode)

    def release_access_heartbeat(self):
        with self._state_lock:
            self._heartbeat_access = None
            self._heartbeat_access_deadline = None

    def _heartbeat_snapshot(self, document):
        with self._state_lock:
            if self._heartbeat_access is not None:
                if self.now() >= self._heartbeat_access_deadline:
                    raise Rejected(503, 'FIXTURE_HEARTBEAT_SNAPSHOT_EXPIRED')
                # Only the prior access report is delayed, never the socket.
                if 'attachments' in document:
                    for receipt in document['attachments']:
                        receipt['access_mode'] = self._heartbeat_access
                else:
                    document['access_mode'] = self._heartbeat_access
                self.heartbeat_observed.set()
        return document

    def heartbeat(self, host, payload):
        status, document = super().heartbeat(host, payload)
        return status, self._heartbeat_snapshot(document)

    def heartbeat_workspaces(self, host, payload):
        status, document = super().heartbeat_workspaces(host, payload)
        return status, self._heartbeat_snapshot(document)

    def stop(self):
        self.release_access_heartbeat()
        super().stop()
