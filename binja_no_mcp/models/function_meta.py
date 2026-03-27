from __future__ import annotations

from dataclasses import dataclass

from ..naming import hex_addr


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
    caller_count: int
    callee_count: int
    callers: list[int]
    callees: list[int]
    export_error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "start": hex_addr(self.start),
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
            "caller_count": self.caller_count,
            "callee_count": self.callee_count,
            "callers": [hex_addr(addr) for addr in self.callers],
            "callees": [hex_addr(addr) for addr in self.callees],
            "export_error": self.export_error,
        }

    def to_index_record(self, meta_file: str) -> dict[str, object]:
        return {
            "start": hex_addr(self.start),
            "name": self.name,
            "raw_name": self.raw_name,
            "sanitized_name": self.sanitized_name,
            "hlil_file": self.hlil_file,
            "pseudoc_file": self.pseudoc_file,
            "mlil_file": self.mlil_file,
            "mlil_ssa_file": self.mlil_ssa_file,
            "llil_file": self.llil_file,
            "meta_file": meta_file,
            "export_error": self.export_error,
        }
