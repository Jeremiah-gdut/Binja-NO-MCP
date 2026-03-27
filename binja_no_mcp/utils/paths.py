from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ExportPaths:
    root: Path
    meta_dir: Path
    functions_dir: Path
    data_dir: Path
    optional_dir: Path
    pseudoc_dir: Path
    mlil_dir: Path
    mlil_ssa_dir: Path
    llil_dir: Path

    @classmethod
    def from_root(cls, root: Path) -> "ExportPaths":
        return cls(
            root=root,
            meta_dir=root / "meta",
            functions_dir=root / "functions",
            data_dir=root / "data",
            optional_dir=root / "optional",
            pseudoc_dir=root / "optional" / "pseudoc",
            mlil_dir=root / "optional" / "mlil",
            mlil_ssa_dir=root / "optional" / "mlil_ssa",
            llil_dir=root / "optional" / "llil",
        )

    @property
    def binary_meta_path(self) -> Path:
        return self.meta_dir / "binary.json"

    @property
    def export_config_path(self) -> Path:
        return self.meta_dir / "export_config.json"

    @property
    def function_index_path(self) -> Path:
        return self.meta_dir / "function_index.jsonl"

    @property
    def failures_path(self) -> Path:
        return self.meta_dir / "failures.jsonl"

    @property
    def sections_path(self) -> Path:
        return self.meta_dir / "sections.json"

    @property
    def segments_path(self) -> Path:
        return self.meta_dir / "segments.json"

    @property
    def strings_path(self) -> Path:
        return self.data_dir / "strings.jsonl"

    @property
    def data_vars_path(self) -> Path:
        return self.data_dir / "data_vars.jsonl"

    @property
    def symbols_path(self) -> Path:
        return self.data_dir / "symbols.jsonl"
