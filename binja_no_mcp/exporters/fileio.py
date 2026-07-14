from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterable, Mapping

from ..utils import ExportPaths


def prepare_output_tree(paths: ExportPaths, overwrite: bool, *, reuse_existing: bool = False) -> None:
    managed_dirs = [
        paths.meta_dir,
        paths.functions_dir,
        paths.data_dir,
        paths.optional_dir,
    ]
    if reuse_existing:
        for directory in [paths.root, *managed_dirs]:
            directory.mkdir(parents=True, exist_ok=True)
        return
    if not overwrite and any(directory.exists() for directory in managed_dirs):
        raise FileExistsError(f"output tree already exists under {paths.root}")
    if overwrite:
        for directory in managed_dirs:
            if directory.exists():
                shutil.rmtree(directory)
    for directory in [paths.root, *managed_dirs]:
        directory.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(contents, encoding="utf-8")
    tmp_path.replace(path)


def write_json(path: Path, payload: Mapping[str, object] | list[object]) -> None:
    write_text(path, json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def write_jsonl_records(path: Path, records: Iterable[Mapping[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
