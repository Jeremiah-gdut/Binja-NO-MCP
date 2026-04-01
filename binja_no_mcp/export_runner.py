from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .collectors import (
    build_function_meta,
    collect_binary_metadata,
    collect_data_var_records,
    collect_section_records,
    collect_segment_records,
    collect_string_records,
    collect_symbol_records,
    function_declaration,
    function_identity,
    resolve_recognized_functions,
)
from .config import ExportConfig
from .exporters import prepare_output_tree, write_json, write_jsonl_records, write_text
from .models import ExportSummary
from .naming import function_file_stem
from .renderers import render_hlil, render_il_listing, render_pseudoc
from .utils import ExportPaths


FunctionKey = tuple[int, str | None]


@dataclass(slots=True)
class ExportSession:
    cfg: ExportConfig
    paths: ExportPaths
    function_keys: list[FunctionKey]
    index_records: list[dict[str, object]] = field(default_factory=list)
    failures: list[dict[str, object]] = field(default_factory=list)
    hlil_exported: int = 0
    pseudoc_exported: int = 0
    mlil_exported: int = 0
    mlil_ssa_exported: int = 0
    llil_exported: int = 0
    meta_exported: int = 0
    strings_exported: int = 0
    data_vars_exported: int = 0
    symbols_exported: int = 0


def _failure_record(start: int | None, name: str | None, phase: str, error: Exception | str) -> dict[str, object]:
    return {
        "start": None if start is None else f"0x{start:016x}",
        "name": name,
        "phase": phase,
        "error": str(error),
    }


def _record_function_error(function_errors: list[str], phase: str, error: Exception | str) -> None:
    function_errors.append(f"{phase}: {error}")


def _export_global_records(session: ExportSession, bv: object) -> None:
    cfg = session.cfg
    paths = session.paths

    if cfg.export_sections:
        try:
            write_json(paths.sections_path, collect_section_records(bv))
        except Exception as exc:
            session.failures.append(_failure_record(None, None, "sections", exc))

    if cfg.export_segments:
        try:
            write_json(paths.segments_path, collect_segment_records(bv))
        except Exception as exc:
            session.failures.append(_failure_record(None, None, "segments", exc))

    if cfg.export_strings:
        try:
            string_records = collect_string_records(bv)
            write_jsonl_records(paths.strings_path, string_records)
            session.strings_exported = len(string_records)
        except Exception as exc:
            session.failures.append(_failure_record(None, None, "strings", exc))

    if cfg.export_data_vars:
        try:
            data_var_records = collect_data_var_records(bv)
            write_jsonl_records(paths.data_vars_path, data_var_records)
            session.data_vars_exported = len(data_var_records)
        except Exception as exc:
            session.failures.append(_failure_record(None, None, "data_vars", exc))

    if cfg.export_symbols:
        try:
            symbol_records = collect_symbol_records(bv)
            write_jsonl_records(paths.symbols_path, symbol_records)
            session.symbols_exported = len(symbol_records)
        except Exception as exc:
            session.failures.append(_failure_record(None, None, "symbols", exc))


def _resolve_one_function(bv: object, function_key: FunctionKey) -> object | None:
    resolved = resolve_recognized_functions(bv, [function_key])
    return resolved[0] if resolved else None


def _export_hlil_family_for_function(session: ExportSession, bv: object, func: object) -> tuple[str | None, str | None, list[str]]:
    hlil_file: str | None = None
    pseudoc_file: str | None = None
    errors: list[str] = []
    cfg = session.cfg

    if not (cfg.export_hlil or cfg.export_pseudoc):
        return hlil_file, pseudoc_file, errors

    declaration = function_declaration(func)
    name, raw_name, _ = function_identity(func)
    stem = function_file_stem(func.start, raw_name)
    produced = False

    for hlil in bv.hlil_functions(function_generator=(item for item in [func])):
        produced = True
        if cfg.export_hlil:
            try:
                hlil_file = f"{stem}.hlil.txt"
                write_text(session.paths.functions_dir / hlil_file, render_hlil(hlil, declaration))
                session.hlil_exported += 1
            except Exception as exc:
                _record_function_error(errors, "hlil", exc)
                session.failures.append(_failure_record(func.start, name, "hlil", exc))
        if cfg.export_pseudoc:
            try:
                pseudoc_file = f"{stem}.pseudoc.c"
                write_text(session.paths.pseudoc_dir / pseudoc_file, render_pseudoc(hlil, declaration))
                session.pseudoc_exported += 1
            except Exception as exc:
                _record_function_error(errors, "pseudoc", exc)
                session.failures.append(_failure_record(func.start, name, "pseudoc", exc))
        break

    if not produced:
        if cfg.export_hlil:
            message = "Binary Ninja did not yield an HLIL function"
            _record_function_error(errors, "hlil", message)
            session.failures.append(_failure_record(func.start, name, "hlil", message))
        if cfg.export_pseudoc:
            message = "Binary Ninja did not yield an HLIL function for pseudo-C rendering"
            _record_function_error(errors, "pseudoc", message)
            session.failures.append(_failure_record(func.start, name, "pseudoc", message))

    return hlil_file, pseudoc_file, errors


def _export_mlil_family_for_function(session: ExportSession, bv: object, func: object) -> tuple[str | None, str | None, list[str]]:
    mlil_file: str | None = None
    mlil_ssa_file: str | None = None
    errors: list[str] = []
    cfg = session.cfg

    if not (cfg.export_mlil or cfg.export_mlil_ssa):
        return mlil_file, mlil_ssa_file, errors

    name, raw_name, _ = function_identity(func)
    stem = function_file_stem(func.start, raw_name)
    produced = False

    for mlil in bv.mlil_functions(function_generator=(item for item in [func])):
        produced = True
        if cfg.export_mlil:
            try:
                mlil_file = f"{stem}.mlil.txt"
                write_text(session.paths.mlil_dir / mlil_file, render_il_listing(mlil))
                session.mlil_exported += 1
            except Exception as exc:
                _record_function_error(errors, "mlil", exc)
                session.failures.append(_failure_record(func.start, name, "mlil", exc))
        if cfg.export_mlil_ssa:
            try:
                ssa_form = getattr(mlil, "ssa_form", None)
                if ssa_form is None:
                    raise ValueError("MLIL SSA unavailable")
                mlil_ssa_file = f"{stem}.mlil_ssa.txt"
                write_text(session.paths.mlil_ssa_dir / mlil_ssa_file, render_il_listing(ssa_form))
                session.mlil_ssa_exported += 1
            except Exception as exc:
                _record_function_error(errors, "mlil_ssa", exc)
                session.failures.append(_failure_record(func.start, name, "mlil_ssa", exc))
        break

    if not produced:
        if cfg.export_mlil:
            message = "Binary Ninja did not yield an MLIL function"
            _record_function_error(errors, "mlil", message)
            session.failures.append(_failure_record(func.start, name, "mlil", message))
        if cfg.export_mlil_ssa:
            message = "Binary Ninja did not yield an MLIL function for SSA rendering"
            _record_function_error(errors, "mlil_ssa", message)
            session.failures.append(_failure_record(func.start, name, "mlil_ssa", message))

    return mlil_file, mlil_ssa_file, errors


def _export_llil_for_function(session: ExportSession, func: object) -> tuple[str | None, list[str]]:
    llil_file: str | None = None
    errors: list[str] = []
    if not session.cfg.export_llil:
        return llil_file, errors

    name, raw_name, _ = function_identity(func)
    stem = function_file_stem(func.start, raw_name)
    try:
        llil = getattr(func, "low_level_il", None)
        if llil is None:
            raise ValueError("LLIL unavailable")
        llil_file = f"{stem}.llil.txt"
        write_text(session.paths.llil_dir / llil_file, render_il_listing(llil))
        session.llil_exported += 1
    except Exception as exc:
        _record_function_error(errors, "llil", exc)
        session.failures.append(_failure_record(func.start, name, "llil", exc))
    return llil_file, errors


def prepare_export_session(bv: object, cfg: ExportConfig, function_keys: list[FunctionKey]) -> ExportSession:
    paths = ExportPaths.from_root(Path(cfg.output_dir))
    prepare_output_tree(paths, cfg.overwrite)
    session = ExportSession(cfg=cfg, paths=paths, function_keys=function_keys)
    write_json(paths.export_config_path, cfg.to_dict())
    write_json(paths.binary_meta_path, collect_binary_metadata(bv, len(function_keys)))
    return session


def export_function(session: ExportSession, bv: object, function_key: FunctionKey) -> None:
    func = _resolve_one_function(bv, function_key)
    start, _ = function_key
    if func is None:
        session.failures.append(_failure_record(start, None, "resolve", "Function disappeared before export"))
        return
    if getattr(func, "needs_update", False):
        name, _, _ = function_identity(func)
        session.failures.append(
            _failure_record(int(getattr(func, "start", start)), name, "analysis", "Function still needs analysis update")
        )
        return

    function_errors: list[str] = []
    hlil_file, pseudoc_file, hlil_errors = _export_hlil_family_for_function(session, bv, func)
    function_errors.extend(hlil_errors)
    mlil_file, mlil_ssa_file, mlil_errors = _export_mlil_family_for_function(session, bv, func)
    function_errors.extend(mlil_errors)
    llil_file, llil_errors = _export_llil_for_function(session, func)
    function_errors.extend(llil_errors)

    name, raw_name, _ = function_identity(func)
    stem = function_file_stem(func.start, raw_name)
    meta = build_function_meta(
        func,
        hlil_file=hlil_file,
        pseudoc_file=pseudoc_file,
        mlil_file=mlil_file,
        mlil_ssa_file=mlil_ssa_file,
        llil_file=llil_file,
        export_error="; ".join(function_errors) if function_errors else None,
    )
    meta_name = f"{stem}.meta.json"
    try:
        write_json(session.paths.functions_dir / meta_name, meta.to_dict())
        session.index_records.append(meta.to_index_record(meta_name))
        session.meta_exported += 1
    except Exception as exc:
        session.failures.append(_failure_record(func.start, name, "meta", exc))


def finalize_export_session(session: ExportSession, bv: object) -> ExportSummary:
    _export_global_records(session, bv)
    write_json(session.paths.binary_meta_path, collect_binary_metadata(bv, len(session.function_keys)))
    write_jsonl_records(session.paths.function_index_path, session.index_records)
    if session.cfg.write_failures:
        write_jsonl_records(session.paths.failures_path, session.failures)

    return ExportSummary(
        function_count=len(session.function_keys),
        hlil_exported=session.hlil_exported,
        pseudoc_exported=session.pseudoc_exported,
        mlil_exported=session.mlil_exported,
        mlil_ssa_exported=session.mlil_ssa_exported,
        llil_exported=session.llil_exported,
        meta_exported=session.meta_exported,
        strings_exported=session.strings_exported,
        data_vars_exported=session.data_vars_exported,
        symbols_exported=session.symbols_exported,
        failures=len(session.failures),
        output_dir=str(session.paths.root),
    )


def run_export(
    bv: object,
    cfg: ExportConfig,
    function_keys: list[FunctionKey] | None = None,
) -> ExportSummary:
    if function_keys is None:
        resolved = resolve_recognized_functions(bv, None)
        function_keys = [
            (int(getattr(func, "start", 0)), getattr(getattr(func, "arch", None), "name", None))
            for func in resolved
        ]

    session = prepare_export_session(bv, cfg, function_keys)
    for function_key in function_keys:
        export_function(session, bv, function_key)
    return finalize_export_session(session, bv)
