"""Substring-based provenance tracking for untrusted tool output."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any


@dataclass(frozen=True)
class TaintSource:
    source_id: str
    tool_name: str
    output: str


class TaintTracker:
    """Find exact or near-copied substrings in untrusted tool output."""

    def __init__(
        self,
        minimum_match_length: int = 12,
        fuzzy_threshold: float = 0.85,
    ) -> None:
        if minimum_match_length < 1:
            raise ValueError("minimum_match_length must be at least 1.")
        if not 0 < fuzzy_threshold <= 1:
            raise ValueError("fuzzy_threshold must be greater than 0 and at most 1.")
        self.minimum_match_length = minimum_match_length
        self.fuzzy_threshold = fuzzy_threshold
        self._sources: dict[str, TaintSource] = {}

    @property
    def sources(self) -> tuple[TaintSource, ...]:
        return tuple(self._sources.values())

    def record(self, source_id: str, tool_name: str, output: str) -> None:
        if not source_id:
            raise ValueError("source_id must not be empty.")
        self._sources[source_id] = TaintSource(source_id, tool_name, output)

    def sources_in(self, value: Any) -> tuple[str, ...]:
        strings = tuple(self._strings(value))
        if not strings:
            return ()
        return tuple(
            source.source_id
            for source in self._sources.values()
            if any(
                self._contains_match(source.output, candidate)
                for candidate in strings
            )
        )

    def _contains_match(self, source: str, candidate: str) -> bool:
        minimum = self.minimum_match_length
        source = self._normalize(source)
        candidate = self._normalize(candidate)
        if len(source) < minimum or len(candidate) < minimum:
            return False

        source_windows = {
            source[index : index + minimum]
            for index in range(len(source) - minimum + 1)
        }
        candidate_windows = {
            candidate[index : index + minimum]
            for index in range(len(candidate) - minimum + 1)
        }
        if source_windows.intersection(candidate_windows):
            return True

        # Use matching 3-character fragments to narrow fuzzy comparisons.
        indexed_source_windows: dict[str, set[str]] = {}
        for window in source_windows:
            for index in range(len(window) - 2):
                indexed_source_windows.setdefault(window[index : index + 3], set()).add(
                    window
                )

        for candidate_window in candidate_windows:
            candidates: set[str] = set()
            for index in range(len(candidate_window) - 2):
                candidates.update(
                    indexed_source_windows.get(
                        candidate_window[index : index + 3], ()
                    )
                )
            for source_window in candidates:
                if (
                    SequenceMatcher(
                        None,
                        source_window,
                        candidate_window,
                        autojunk=False,
                    ).ratio()
                    >= self.fuzzy_threshold
                ):
                    return True
        return False

    @staticmethod
    def _normalize(value: str) -> str:
        return unicodedata.normalize("NFKC", value).casefold()

    @classmethod
    def _strings(cls, value: Any):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for nested_value in value.values():
                yield from cls._strings(nested_value)
        elif isinstance(value, (list, tuple)):
            for nested_value in value:
                yield from cls._strings(nested_value)
