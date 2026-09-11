"""Native owner grants for disposable OS acceptance accounts.

Keep the legacy protocol fixture available to its existing consumers. Native
lifecycle proofs need production's unique active host/session attachment and
owner-controlled permissions, including across installer upgrades (M445/M1841).
"""
from typing import Any
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
        result = super().complete(host, command_id, payload)
        self.completions[command_id] = payload
        return result
