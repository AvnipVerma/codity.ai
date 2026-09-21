"""Whole-program taint analysis (placeholder until the engine lands)."""

from __future__ import annotations


class TaintProgram:
    def __init__(self, program, rules) -> None:
        self.program = program
        self.rules = rules

    def run(self) -> None:
        pass

    def findings_for(self, path: str) -> list:
        return []
