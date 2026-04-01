from __future__ import annotations

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


def _failure_record(start: int | None, name: str | None, phase: str, error: Exception | str) -> dict[str, object]:
    return {
        "start": None if start is None else f"0x{start:016x}",
        "name": name,
        "phase": phase,
        "error": str(error),
    }


def _record_function_error(function_errors: dict[int, list[str]], start: int, phase: str, error: Exception | str) -> None:
    function_errors.setdefault(start, []).append(f"{phase}: {error}")


def _function_error_text(function_errors: dict[int, list[str]], start: int) -> str | None:
    errors = function_errors.get(start)
    if not errors:
        return None
    return "; ".join(errors)


def _export_global_records(cfg: ExportConfig, bv: object, paths: ExportPaths, failures: list[dict[str, object]]) -> tuple[int, int, int]:
    strings_count = 0
    data_vars_count = 0
    symbols_count = 0

    if cfg.export_sections:
        try:
            write_json(paths.sections_path, collect_section_records(bv))
        except Exception as exc:
            failures.append(_failure_record(None, None, "sections", exc))

    if cfg.export_segments:
        try:
            write_json(paths.segments_path, collect_segment_records(bv))
        except Exception as exc:
            failures.append(_failure_record(None, None, "segments", exc))

    if cfg.export_strings:
        try:
            string_records = collect_string_records(bv)
            write_jsonl_records(paths.strings_path, string_records)
            strings_count = len(string_records)
        except Exception as exc:
            failures.append(_failure_record(None, None, "strings", exc))

    if cfg.export_data_vars:
        try:
            data_var_records = collect_data_var_records(bv)
            write_jsonl_records(paths.data_vars_path, data_var_records)
            data_vars_count = len(data_var_records)
        except Exception as exc:
            failures.append(_failure_record(None, None, "data_vars", exc))

    if cfg.export_symbols:
        try:
            symbol_records = collect_symbol_records(bv)
            write_jsonl_records(paths.symbols_path, symbol_records)
            symbols_count = len(symbol_records)
        except Exception as exc:
            failures.append(_failure_record(None, None, "symbols", exc))

    return strings_count, data_vars_count, symbols_count


def _export_hlil_family(
    bv: object,
    recognized_funcs: list[object],
    cfg: ExportConfig,
    paths: ExportPaths,
    failures: list[dict[str, object]],
    function_errors: dict[int, list[str]],
) -> tuple[dict[int, str], dict[int, str]]:
    hlil_files: dict[int, str] = {}
    pseudoc_files: dict[int, str] = {}
    if not (cfg.export_hlil or cfg.export_pseudoc):
        return hlil_files, pseudoc_files

    for hlil in bv.hlil_functions(function_generator=(func for func in recognized_funcs)):
        func = hlil.source_function
        name, raw_name, _ = function_identity(func)
        stem = function_file_stem(func.start, raw_name)
        declaration = function_declaration(func)
        if cfg.export_hlil:
            try:
                file_name = f"{stem}.hlil.txt"
                write_text(paths.functions_dir / file_name, render_hlil(hlil, declaration))
                hlil_files[func.start] = file_name
            except Exception as exc:
                _record_function_error(function_errors, func.start, "hlil", exc)
                failures.append(_failure_record(func.start, name, "hlil", exc))
        if cfg.export_pseudoc:
            try:
                file_name = f"{stem}.pseudoc.c"
                write_text(paths.pseudoc_dir / file_name, render_pseudoc(hlil, declaration))
                pseudoc_files[func.start] = file_name
            except Exception as exc:
                _record_function_error(function_errors, func.start, "pseudoc", exc)
                failures.append(_failure_record(func.start, name, "pseudoc", exc))
    return hlil_files, pseudoc_files


def _export_mlil_family(
    bv: object,
    recognized_funcs: list[object],
    cfg: ExportConfig,
    paths: ExportPaths,
    failures: list[dict[str, object]],
    function_errors: dict[int, list[str]],
) -> tuple[dict[int, str], dict[int, str]]:
    mlil_files: dict[int, str] = {}
    mlil_ssa_files: dict[int, str] = {}
    if not (cfg.export_mlil or cfg.export_mlil_ssa):
        return mlil_files, mlil_ssa_files

    seen: set[int] = set()
    for mlil in bv.mlil_functions(function_generator=(func for func in recognized_funcs)):
        func = mlil.source_function
        seen.add(func.start)
        name, raw_name, _ = function_identity(func)
        stem = function_file_stem(func.start, raw_name)

        if cfg.export_mlil:
            try:
                file_name = f"{stem}.mlil.txt"
                write_text(paths.mlil_dir / file_name, render_il_listing(mlil))
                mlil_files[func.start] = file_name
            except Exception as exc:
                _record_function_error(function_errors, func.start, "mlil", exc)
                failures.append(_failure_record(func.start, name, "mlil", exc))

        if cfg.export_mlil_ssa:
            try:
                ssa_form = getattr(mlil, "ssa_form", None)
                if ssa_form is None:
                    raise ValueError("MLIL SSA unavailable")
                file_name = f"{stem}.mlil_ssa.txt"
                write_text(paths.mlil_ssa_dir / file_name, render_il_listing(ssa_form))
                mlil_ssa_files[func.start] = file_name
            except Exception as exc:
                _record_function_error(function_errors, func.start, "mlil_ssa", exc)
                failures.append(_failure_record(func.start, name, "mlil_ssa", exc))

    for func in recognized_funcs:
        if func.start in seen:
            continue
        name, _, _ = function_identity(func)
        if cfg.export_mlil:
            message = "MLIL export skipped because Binary Ninja did not yield an MLIL function"
            _record_function_error(function_errors, func.start, "mlil", message)
            failures.append(_failure_record(func.start, name, "mlil", message))
        if cfg.export_mlil_ssa:
            message = "MLIL SSA export skipped because Binary Ninja did not yield an MLIL function"
            _record_function_error(function_errors, func.start, "mlil_ssa", message)
            failures.append(_failure_record(func.start, name, "mlil_ssa", message))

    return mlil_files, mlil_ssa_files


def _export_llil(
    recognized_funcs: list[object],
    cfg: ExportConfig,
    paths: ExportPaths,
    failures: list[dict[str, object]],
    function_errors: dict[int, list[str]],
) -> dict[int, str]:
    llil_files: dict[int, str] = {}
    if not cfg.export_llil:
        return llil_files

    for func in recognized_funcs:
        name, raw_name, _ = function_identity(func)
        stem = function_file_stem(func.start, raw_name)
        try:
            llil = getattr(func, "low_level_il", None)
            if llil is None:
                raise ValueError("LLIL unavailable")
            file_name = f"{stem}.llil.txt"
            write_text(paths.llil_dir / file_name, render_il_listing(llil))
            llil_files[func.start] = file_name
        except Exception as exc:
            _record_function_error(function_errors, func.start, "llil", exc)
            failures.append(_failure_record(func.start, name, "llil", exc))

    return llil_files


def run_export(
    bv: object,
    cfg: ExportConfig,
    function_keys: list[tuple[int, str | None]] | None = None,
) -> ExportSummary:
    paths = ExportPaths.from_root(Path(cfg.output_dir))
    prepare_output_tree(paths, cfg.overwrite)

    recognized_funcs = resolve_recognized_functions(bv, function_keys)
    failures: list[dict[str, object]] = []
    function_errors: dict[int, list[str]] = {}

    write_json(paths.export_config_path, cfg.to_dict())
    write_json(paths.binary_meta_path, collect_binary_metadata(bv, len(recognized_funcs)))

    strings_count, data_vars_count, symbols_count = _export_global_records(cfg, bv, paths, failures)
    hlil_files, pseudoc_files = _export_hlil_family(bv, recognized_funcs, cfg, paths, failures, function_errors)
    mlil_files, mlil_ssa_files = _export_mlil_family(bv, recognized_funcs, cfg, paths, failures, function_errors)
    llil_files = _export_llil(recognized_funcs, cfg, paths, failures, function_errors)

    index_records: list[dict[str, object]] = []
    meta_count = 0
    for func in recognized_funcs:
        name, raw_name, _ = function_identity(func)
        stem = function_file_stem(func.start, raw_name)
        meta = build_function_meta(
            func,
            hlil_file=hlil_files.get(func.start),
            pseudoc_file=pseudoc_files.get(func.start),
            mlil_file=mlil_files.get(func.start),
            mlil_ssa_file=mlil_ssa_files.get(func.start),
            llil_file=llil_files.get(func.start),
            export_error=_function_error_text(function_errors, func.start),
        )
        meta_name = f"{stem}.meta.json"
        try:
            write_json(paths.functions_dir / meta_name, meta.to_dict())
            index_records.append(meta.to_index_record(meta_name))
            meta_count += 1
        except Exception as exc:
            failures.append(_failure_record(func.start, name, "meta", exc))

    write_jsonl_records(paths.function_index_path, index_records)
    if cfg.write_failures:
        write_jsonl_records(paths.failures_path, failures)

    return ExportSummary(
        function_count=len(recognized_funcs),
        hlil_exported=len(hlil_files),
        pseudoc_exported=len(pseudoc_files),
        mlil_exported=len(mlil_files),
        mlil_ssa_exported=len(mlil_ssa_files),
        llil_exported=len(llil_files),
        meta_exported=meta_count,
        strings_exported=strings_count,
        data_vars_exported=data_vars_count,
        symbols_exported=symbols_count,
        failures=len(failures),
        output_dir=str(paths.root),
    )
