"""Command-line entry point for the Phase 1 offline demo."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from .detector import DEFAULT_THRESHOLD, evaluate_detector
from .firewall import CordonFirewall, FirewallDecision
from .llm import MockLLM
from .loop import ToolLoop, ToolLoopLimitError
from .tools import FakeTools


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cordon",
        description="Run the offline CORDON Phase 1 tool-calling demo.",
    )
    parser.add_argument(
        "--cordon",
        choices=("off", "on"),
        default="off",
        help="Enable or disable the Phase 2/3 local tool firewall (default: off).",
    )
    parser.add_argument(
        "--gullible",
        action="store_true",
        help="Make MockLLM follow the fake malicious email instructions.",
    )
    parser.add_argument(
        "--sandbox-dir",
        type=Path,
        help="Use this sandbox directory instead of a temporary one.",
    )
    parser.add_argument(
        "--allow-recipient",
        action="append",
        default=[],
        metavar="EMAIL",
        help="Approve a fake email recipient when Cordon is on; may be repeated.",
    )
    parser.add_argument(
        "--detector-threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        metavar="0..1",
        help=f"Injection detector threshold (default: {DEFAULT_THRESHOLD}).",
    )
    parser.add_argument(
        "--evaluate-detector",
        action="store_true",
        help="Report detector rates on bundled injection and benign samples.",
    )
    return parser


def _request_approval(
    tool_name: str,
    arguments: dict[str, object],
    decision: FirewallDecision,
) -> bool:
    print(
        f"R5: suspicious context detected ({', '.join(decision.source_ids)})."
    )
    print(f"Requested tool: {tool_name}({arguments!r})")
    try:
        answer = input("Approve this tool call? [y/N] ").strip().casefold()
    except EOFError:
        print("No approval received; blocking the tool call.")
        return False
    return answer in {"y", "yes"}


def run_demo(
    sandbox: Path,
    gullible: bool,
    cordon: bool = False,
    allowed_recipients: list[str] | None = None,
    detector_threshold: float = DEFAULT_THRESHOLD,
) -> tuple[str, ToolLoop]:
    tools = FakeTools(sandbox)
    firewall = (
        CordonFirewall(
            allowed_recipients=allowed_recipients or [],
            detector_threshold=detector_threshold,
        )
        if cordon
        else None
    )
    loop = ToolLoop(
        MockLLM(gullible=gullible),
        tools,
        firewall=firewall,
        approval_handler=_request_approval if cordon else None,
    )
    return loop.run("Review my latest email and handle it."), loop


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not 0 <= args.detector_threshold <= 1:
        print("Error: --detector-threshold must be between 0 and 1.")
        return 2
    if args.evaluate_detector:
        results = evaluate_detector(args.detector_threshold)
        print(
            "Injection detection: "
            f"{results['injection_detected']}/{results['injection_total']} "
            f"({results['detection_rate']:.1%})"
        )
        print(
            "Benign flag rate: "
            f"{results['benign_flagged']}/{results['benign_total']} "
            f"({results['benign_flag_rate']:.1%})"
        )
        return 0
    print(f"CORDON offline demo: fake tools only; Cordon is {args.cordon}.")
    try:
        if args.sandbox_dir:
            response, loop = run_demo(
                args.sandbox_dir,
                args.gullible,
                cordon=args.cordon == "on",
                allowed_recipients=args.allow_recipient,
                detector_threshold=args.detector_threshold,
            )
            sandbox = args.sandbox_dir.resolve()
        else:
            with tempfile.TemporaryDirectory(prefix="cordon-demo-") as path:
                sandbox = Path(path)
                response, loop = run_demo(
                    sandbox,
                    args.gullible,
                    cordon=args.cordon == "on",
                    allowed_recipients=args.allow_recipient,
                    detector_threshold=args.detector_threshold,
                )
                _print_results(response, sandbox, loop)
                return 0
    except ToolLoopLimitError as error:
        print(f"Error: {error}")
        return 1
    _print_results(response, sandbox, loop)
    return 0


def _print_results(response: str, sandbox: Path, loop: ToolLoop) -> None:
    outbox = sandbox / "outbox"
    messages = sorted(outbox.glob("message-*.txt")) if outbox.exists() else []
    print(f"Assistant: {response}")
    for tool_name, decision in loop.firewall_events:
        if not decision.allowed:
            print(
                f"CORDON blocked {tool_name} ({decision.rule_id}): "
                f"{decision.reason}"
            )
            if decision.source_ids:
                print(f"  Taint sources: {', '.join(decision.source_ids)}")
    if messages:
        for message in messages:
            print(f"Fake outbox ({message.name}):")
            print(message.read_text(encoding="utf-8").rstrip())
    else:
        print("Fake outbox: empty")


if __name__ == "__main__":
    raise SystemExit(main())
