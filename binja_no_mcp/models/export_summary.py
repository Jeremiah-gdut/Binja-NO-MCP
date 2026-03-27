from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class ExportSummary:
    function_count: int
    hlil_exported: int
    pseudoc_exported: int
    mlil_exported: int
    mlil_ssa_exported: int
    llil_exported: int
    meta_exported: int
    strings_exported: int
    data_vars_exported: int
    symbols_exported: int
    failures: int
    output_dir: str

    def to_dict(self) -> dict[str, object]:
        return {
            "function_count": self.function_count,
            "hlil_exported": self.hlil_exported,
            "pseudoc_exported": self.pseudoc_exported,
            "mlil_exported": self.mlil_exported,
            "mlil_ssa_exported": self.mlil_ssa_exported,
            "llil_exported": self.llil_exported,
            "meta_exported": self.meta_exported,
            "strings_exported": self.strings_exported,
            "data_vars_exported": self.data_vars_exported,
            "symbols_exported": self.symbols_exported,
            "failures": self.failures,
            "output_dir": self.output_dir,
        }
