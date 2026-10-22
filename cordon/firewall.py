"""Local policy firewall for model-requested tool calls."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Iterable

from .detector import DEFAULT_THRESHOLD, DetectionResult, detect
from .taint import TaintTracker


@dataclass(frozen=True)
class FirewallDecision:
    allowed: bool
    reason: str
    rule_id: str | None = None
    source_ids: tuple[str, ...] = ()


class CordonFirewall:
    """Apply conservative policies before any fake tool is executed."""

    _PROTECTED_NAMES = frozenset(
        {
            ".env",
            "credentials.json",
            "id_ed25519",
            "id_rsa",
            "secrets.txt",
        }
    )

    def __init__(
        self,
        allowed_recipients: Iterable[str] = (),
        taint_tracker: TaintTracker | None = None,
        detector_threshold: float = DEFAULT_THRESHOLD,
    ) -> None:
        self.allowed_recipients = frozenset(
            recipient.strip().casefold()
            for recipient in allowed_recipients
            if recipient.strip()
        )
        self.taint_tracker = taint_tracker or TaintTracker()
        self.detector_threshold = detector_threshold
        self.context_suspicious = False
        self.context_detections: list[tuple[str, DetectionResult]] = []
        if not 0 <= detector_threshold <= 1:
            raise ValueError("detector_threshold must be between 0 and 1.")

    def record_tool_output(
        self,
        source_id: str,
        tool_name: str,
        output: str,
    ) -> None:
        self.taint_tracker.record(source_id, tool_name, output)
        detection = detect(output, threshold=self.detector_threshold)
        self.context_detections.append((source_id, detection))
        self.context_suspicious = self.context_suspicious or detection.context_suspicious

    def check(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        approved: bool = False,
    ) -> FirewallDecision:
        if (
            self.context_suspicious
            and tool_name in {"send_email", "delete_file", "read_file"}
            and not approved
        ):
            source_ids = tuple(
                source_id
                for source_id, detection in self.context_detections
                if detection.context_suspicious
            )
            return FirewallDecision(
                False,
                "the context contains a prompt-injection indicator",
                "R5",
                source_ids,
            )

        if tool_name in {"read_file", "write_file", "delete_file"}:
            path = arguments.get("path")
            if not isinstance(path, str) or not path.strip():
                return FirewallDecision(
                    False,
                    "file path is missing or invalid",
                    "protected-file",
                )
            if tool_name == "delete_file":
                source_ids = self.taint_tracker.sources_in(path)
                if source_ids:
                    return FirewallDecision(
                        False,
                        "file path contains copied untrusted content",
                        "R4",
                        source_ids,
                    )
            normalized = path.replace("\\", "/")
            if PurePosixPath(normalized).name.casefold() in self._PROTECTED_NAMES:
                return FirewallDecision(
                    False,
                    "access to a protected file is denied",
                    "protected-file",
                )

        if tool_name == "send_email":
            tainted_sources = tuple(
                sorted(
                    set(self.taint_tracker.sources_in(arguments.get("to")))
                    | set(self.taint_tracker.sources_in(arguments.get("body")))
                )
            )
            if tainted_sources:
                return FirewallDecision(
                    False,
                    "recipient or message body contains copied untrusted content",
                    "R3",
                    tainted_sources,
                )
            recipient = arguments.get("to")
            if (
                not isinstance(recipient, str)
                or recipient.strip().casefold() not in self.allowed_recipients
            ):
                return FirewallDecision(
                    False,
                    "recipient is not explicitly approved",
                    "email-approval",
                )

        return FirewallDecision(True, "allowed by policy", "allow")
