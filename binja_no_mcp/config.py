from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class ExportConfig:
    output_dir: Path
    reanalyze_before_export: bool = True
    export_hlil: bool = True
    export_pseudoc: bool = False
    export_mlil: bool = False
    export_mlil_ssa: bool = False
    export_llil: bool = False
    export_strings: bool = True
    export_data_vars: bool = True
    export_sections: bool = True
    export_segments: bool = True
    export_symbols: bool = True
    batch_size: int = 64
    overwrite: bool = True
    write_failures: bool = True
    function_time_limit_seconds: int = 900
    private_memory_limit_gib: int = 24
    incremental: bool = False

    def __post_init__(self) -> None:
        output_dir = Path(self.output_dir).expanduser()
        object.__setattr__(self, "output_dir", output_dir)
        if self.batch_size < 1:
            raise ValueError("batch_size must be at least 1")
        if self.function_time_limit_seconds < 1:
            raise ValueError("function_time_limit_seconds must be at least 1")
        if self.private_memory_limit_gib < 1:
            raise ValueError("private_memory_limit_gib must be at least 1")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["output_dir"] = str(self.output_dir)
        return data
