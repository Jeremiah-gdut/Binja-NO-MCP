from __future__ import annotations

from dataclasses import dataclass

from ..naming import function_id


@dataclass(slots=True)
class FunctionMeta:
    start: int
    name: str
    raw_name: str
    sanitized_name: str
    declaration: str | None
    prototype: dict[str, object]
    symbol_name: str | None
    calling_convention: str | None
    can_return: bool | None
    hlil_available: bool
    hlil_file: str | None
    pseudoc_file: str | None
    mlil_file: str | None
    mlil_ssa_file: str | None
    llil_file: str | None
    call_evidence: list[dict[str, str]]
    export_error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "id": function_id(self.start),
            "start": function_id(self.start),
            "name": self.name,
            "raw_name": self.raw_name,
            "sanitized_name": self.sanitized_name,
            "declaration": self.declaration,
            "prototype": self.prototype,
            "symbol_name": self.symbol_name,
            "calling_convention": self.calling_convention,
            "can_return": self.can_return,
            "hlil_available": self.hlil_available,
            "hlil_file": self.hlil_file,
            "pseudoc_file": self.pseudoc_file,
            "mlil_file": self.mlil_file,
            "mlil_ssa_file": self.mlil_ssa_file,
            "llil_file": self.llil_file,
            "call_evidence": self.call_evidence,
            "export_error": self.export_error,
        }

    def to_index_record(self, meta_file: str) -> dict[str, object]:
        artifacts = {"meta": f"functions/{meta_file}"}
        if self.hlil_file:
            artifacts["hlil"] = f"functions/{self.hlil_file}"
        if self.pseudoc_file:
            artifacts["pseudoc"] = f"optional/pseudoc/{self.pseudoc_file}"
        if self.mlil_file:
            artifacts["mlil"] = f"optional/mlil/{self.mlil_file}"
        if self.mlil_ssa_file:
            artifacts["mlil_ssa"] = f"optional/mlil_ssa/{self.mlil_ssa_file}"
        if self.llil_file:
            artifacts["llil"] = f"optional/llil/{self.llil_file}"
        return {
            "id": function_id(self.start),
            "name": self.name,
            "declaration": self.declaration,
            "artifacts": artifacts,
            "export_status": "partial" if self.export_error else "exported",
            "export_error": self.export_error,
            "startup_stages": [],
        }
