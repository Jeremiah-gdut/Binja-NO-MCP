from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic
from typing import Callable

from .collectors import (
    build_function_meta,
    collect_binary_metadata,
    collect_call_evidence,
    collect_data_var_records,
    collect_section_records,
    collect_segment_records,
    collect_string_records,
    collect_symbol_records,
    collect_startup_entries,
    function_declaration,
    function_identity,
    resolve_recognized_functions,
)
from .config import ExportConfig
from .exporters import prepare_output_tree, write_json, write_jsonl_records, write_text
from .models import ExportSummary
from .naming import function_file_stem, function_id
from .renderers import render_hlil, render_il_listing, render_pseudoc
from .resource_monitor import ProcessMemoryMonitor
from .utils import ExportPaths


FunctionKey = tuple[int, str | None]


def _required_artifacts(cfg: ExportConfig) -> set[str]:
    artifacts = {"meta"}
    if cfg.export_hlil:
        artifacts.add("hlil")
    if cfg.export_pseudoc:
        artifacts.add("pseudoc")
    if cfg.export_mlil:
        artifacts.add("mlil")
    if cfg.export_mlil_ssa:
        artifacts.add("mlil_ssa")
    if cfg.export_llil:
        artifacts.add("llil")
    return artifacts


def _record_has_required_artifacts(paths: ExportPaths, record: dict[str, object], required: set[str]) -> bool:
    artifacts = record.get("artifacts")
    if not isinstance(artifacts, dict):
        return False
    for artifact in required:
        relative_path = artifacts.get(artifact)
        if not isinstance(relative_path, str) or not (paths.root / relative_path).is_file():
            return False
    return True


def _load_reused_index_records(
    paths: ExportPaths, bv: object, cfg: ExportConfig, function_keys: list[FunctionKey]
) -> list[dict[str, object]]:
    if not paths.binary_meta_path.is_file():
        raise FileNotFoundError(f"Incremental export requires {paths.binary_meta_path}")
    if not paths.function_index_path.is_file():
        raise FileNotFoundError(f"Incremental export requires {paths.function_index_path}")

    try:
        binary_meta = json.loads(paths.binary_meta_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Incremental export cannot read {paths.binary_meta_path}: {exc}") from exc
    if not isinstance(binary_meta, dict):
        raise ValueError(f"Incremental export requires an object in {paths.binary_meta_path}")

    file_metadata = getattr(bv, "file", None)
    current_filenames = {
        str(filename)
        for filename in (
            getattr(file_metadata, "filename", None),
            getattr(file_metadata, "original_filename", None),
        )
        if filename
    }
    if binary_meta.get("filename") not in current_filenames:
        raise ValueError("Incremental export target does not match the existing snapshot")

    available_ids = {function_id(start) for start, _ in function_keys}
    required_artifacts = _required_artifacts(cfg)
    records_by_id: dict[str, dict[str, object]] = {}
    for line_number, line in enumerate(paths.function_index_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Incremental export cannot read {paths.function_index_path} line {line_number}: {exc}") from exc
        if not isinstance(record, dict):
            raise ValueError(f"Incremental export requires object records in {paths.function_index_path}")
        record_id = record.get("id")
        if (
            isinstance(record_id, str)
            and record_id in available_ids
            and record.get("export_status") == "exported"
            and _record_has_required_artifacts(paths, record, required_artifacts)
        ):
            records_by_id[record_id] = record

    return [records_by_id[function_id(start)] for start, _ in function_keys if function_id(start) in records_by_id]


def _restore_reused_records(session: ExportSession, records: list[dict[str, object]]) -> None:
    starts_by_id = {function_id(start): start for start, _ in session.function_keys}
    for record in records:
        record_id = record.get("id")
        if not isinstance(record_id, str):
            continue
        _append_index_record(session, starts_by_id[record_id], record)
        session.exported_function_count += 1
        artifacts = record.get("artifacts")
        if not isinstance(artifacts, dict):
            continue
        session.meta_exported += int("meta" in artifacts)
        session.hlil_exported += int("hlil" in artifacts)
        session.pseudoc_exported += int("pseudoc" in artifacts)
        session.mlil_exported += int("mlil" in artifacts)
        session.mlil_ssa_exported += int("mlil_ssa" in artifacts)
        session.llil_exported += int("llil" in artifacts)


def _clear_incremental_global_records(paths: ExportPaths) -> None:
    for path in (
        paths.startup_entries_path,
        paths.failures_path,
        paths.sections_path,
        paths.segments_path,
        paths.strings_path,
        paths.data_vars_path,
        paths.symbols_path,
    ):
        path.unlink(missing_ok=True)


@dataclass(slots=True)
class ExportSession:
    cfg: ExportConfig
    paths: ExportPaths
    function_keys: list[FunctionKey]
    index_records: list[dict[str, object]] = field(default_factory=list)
    indexed_starts: set[int] = field(default_factory=set)
    failures: list[dict[str, object]] = field(default_factory=list)
    exported_function_count: int = 0
    cancelled: bool = False
    hlil_exported: int = 0
    pseudoc_exported: int = 0
    mlil_exported: int = 0
    mlil_ssa_exported: int = 0
    llil_exported: int = 0
    meta_exported: int = 0
    strings_exported: int = 0
    data_vars_exported: int = 0
    symbols_exported: int = 0
    memory_monitor: ProcessMemoryMonitor | None = None
    memory_window_active: bool = False
    stop_requested: bool = False


def _failure_record(
    start: int | None,
    name: str | None,
    phase: str,
    error: Exception | str,
    *,
    reason: str | None = None,
    elapsed_seconds: float | None = None,
    memory_window: dict[str, object] | None = None,
) -> dict[str, object]:
    record: dict[str, object] = {
        "start": None if start is None else function_id(start),
        "name": name,
        "phase": phase,
        "error": str(error),
    }
    if reason is not None:
        record["reason"] = reason
    if elapsed_seconds is not None:
        record["elapsed_seconds"] = elapsed_seconds
    if memory_window is not None:
        record["memory_window"] = memory_window
    return record


def _record_function_error(function_errors: list[str], phase: str, error: Exception | str) -> None:
    function_errors.append(f"{phase}: {error}")


def _failed_index_record(
    start: int,
    name: str | None,
    error: Exception | str,
    status: str = "failed",
    *,
    memory_window: dict[str, object] | None = None,
) -> dict[str, object]:
    record: dict[str, object] = {
        "id": function_id(start),
        "name": name,
        "declaration": None,
        "artifacts": {},
        "export_status": status,
        "export_error": str(error),
        "startup_stages": [],
    }
    if memory_window is not None:
        record["memory_window"] = memory_window
    return record


def _partial_index_record(
    start: int,
    name: str,
    declaration: str | None,
    hlil_file: str | None,
    pseudoc_file: str | None,
    mlil_file: str | None,
    mlil_ssa_file: str | None,
    llil_file: str | None,
    error: str,
    *,
    memory_window: dict[str, object] | None = None,
) -> dict[str, object]:
    artifacts: dict[str, str] = {}
    if hlil_file:
        artifacts["hlil"] = f"functions/{hlil_file}"
    if pseudoc_file:
        artifacts["pseudoc"] = f"optional/pseudoc/{pseudoc_file}"
    if mlil_file:
        artifacts["mlil"] = f"optional/mlil/{mlil_file}"
    if mlil_ssa_file:
        artifacts["mlil_ssa"] = f"optional/mlil_ssa/{mlil_ssa_file}"
    if llil_file:
        artifacts["llil"] = f"optional/llil/{llil_file}"
    record: dict[str, object] = {
        "id": function_id(start),
        "name": name,
        "declaration": declaration,
        "artifacts": artifacts,
        "export_status": "partial",
        "export_error": error,
        "startup_stages": [],
    }
    if memory_window is not None:
        record["memory_window"] = memory_window
    return record


def _export_timed_out(deadline: float) -> bool:
    return monotonic() >= deadline


def _memory_ceiling_reached(session: ExportSession) -> bool:
    return session.memory_monitor is not None and session.memory_monitor.exceeded


def _export_cancelled(is_cancelled: Callable[[], bool] | None) -> bool:
    return is_cancelled is not None and is_cancelled()


def begin_memory_window(session: ExportSession) -> None:
    if session.memory_monitor is None or session.memory_window_active:
        return
    session.memory_monitor.begin_window()
    session.memory_window_active = True


def _end_memory_window(session: ExportSession) -> dict[str, object] | None:
    if session.memory_monitor is None or not session.memory_window_active:
        return None
    memory_window = session.memory_monitor.end_window().to_dict()
    session.memory_window_active = False
    return memory_window


def _append_index_record(session: ExportSession, start: int, record: dict[str, object]) -> None:
    if start in session.indexed_starts:
        return
    session.indexed_starts.add(start)
    session.index_records.append(record)


def record_function_analysis_failure(
    session: ExportSession,
    function_key: FunctionKey,
    func: object,
    reason: str,
    elapsed_seconds: float,
) -> None:
    """Record an unexportable function without risking stale analysis artifacts."""

    start, _ = function_key
    name, _, _ = function_identity(func)
    message = {
        "analysis-deferred": "Function analysis exceeded the configured time limit",
        "analysis-unconfirmed": "Function analysis did not reach a confirmed workflow terminal state",
        "skipped": "Function was skipped after a cooperative workflow halt request",
    }.get(reason, "Function analysis did not complete")
    memory_window = _end_memory_window(session)
    session.failures.append(
        _failure_record(
            start,
            name,
            "analysis",
            message,
            reason=reason,
            elapsed_seconds=elapsed_seconds,
            memory_window=memory_window,
        )
    )
    _append_index_record(session, start, _failed_index_record(start, name, message, memory_window=memory_window))


def record_function_memory_ceiling(
    session: ExportSession,
    function_key: FunctionKey,
    func: object,
    elapsed_seconds: float,
) -> None:
    start, _ = function_key
    name, _, _ = function_identity(func)
    message = "Process PrivateUsage reached the configured memory ceiling"
    memory_window = _end_memory_window(session)
    session.failures.append(
        _failure_record(
            start,
            name,
            "memory",
            message,
            reason="memory-ceiling",
            elapsed_seconds=elapsed_seconds,
            memory_window=memory_window,
        )
    )
    _append_index_record(session, start, _failed_index_record(start, name, message, memory_window=memory_window))


def record_function_analysis_cancelled(
    session: ExportSession,
    function_key: FunctionKey,
    func: object,
    elapsed_seconds: float,
) -> None:
    start, _ = function_key
    name, _, _ = function_identity(func)
    message = "Export cancelled while waiting for function analysis"
    memory_window = _end_memory_window(session)
    session.failures.append(
        _failure_record(
            start,
            name,
            "analysis",
            message,
            reason="cancelled",
            elapsed_seconds=elapsed_seconds,
            memory_window=memory_window,
        )
    )
    _append_index_record(
        session,
        start,
        _failed_index_record(start, name, message, "partial", memory_window=memory_window),
    )


def _record_export_timeout(
    session: ExportSession,
    func: object,
    start: int,
    name: str,
    declaration: str | None,
    hlil_file: str | None,
    pseudoc_file: str | None,
    mlil_file: str | None,
    mlil_ssa_file: str | None,
    llil_file: str | None,
    function_errors: list[str],
    started_at: float,
) -> None:
    message = "Function export exceeded the configured time limit"
    elapsed_seconds = monotonic() - started_at
    memory_window = _end_memory_window(session)
    _record_function_error(function_errors, "export-timeout", message)
    session.failures.append(
        _failure_record(
            start,
            name,
            "export",
            message,
            reason="export-timeout",
            elapsed_seconds=elapsed_seconds,
            memory_window=memory_window,
        )
    )
    _append_index_record(
        session,
        start,
        _partial_index_record(
            start,
            name,
            declaration,
            hlil_file,
            pseudoc_file,
            mlil_file,
            mlil_ssa_file,
            llil_file,
            "; ".join(function_errors),
            memory_window=memory_window,
        ),
    )


def _record_export_cancelled(
    session: ExportSession,
    start: int,
    name: str,
    declaration: str | None,
    hlil_file: str | None,
    pseudoc_file: str | None,
    mlil_file: str | None,
    mlil_ssa_file: str | None,
    llil_file: str | None,
    function_errors: list[str],
    started_at: float,
) -> None:
    message = "Export cancelled by the user"
    _record_function_error(function_errors, "cancelled", message)
    memory_window = _end_memory_window(session)
    session.failures.append(
        _failure_record(
            start,
            name,
            "export",
            message,
            reason="cancelled",
            elapsed_seconds=monotonic() - started_at,
            memory_window=memory_window,
        )
    )
    _append_index_record(
        session,
        start,
        _partial_index_record(
            start,
            name,
            declaration,
            hlil_file,
            pseudoc_file,
            mlil_file,
            mlil_ssa_file,
            llil_file,
            "; ".join(function_errors),
            memory_window=memory_window,
        ),
    )
    session.cancelled = True


def _record_memory_ceiling(
    session: ExportSession,
    func: object,
    start: int,
    name: str,
    declaration: str | None,
    hlil_file: str | None,
    pseudoc_file: str | None,
    mlil_file: str | None,
    mlil_ssa_file: str | None,
    llil_file: str | None,
    function_errors: list[str],
    started_at: float,
    memory_window: dict[str, object] | None = None,
) -> None:
    message = "Process PrivateUsage reached the configured memory ceiling"
    _record_function_error(function_errors, "memory-ceiling", message)
    if memory_window is None:
        memory_window = _end_memory_window(session)
    session.failures.append(
        _failure_record(
            start,
            name,
            "memory",
            message,
            reason="memory-ceiling",
            elapsed_seconds=monotonic() - started_at,
            memory_window=memory_window,
        )
    )
    _append_index_record(
        session,
        start,
        _partial_index_record(
            start,
            name,
            declaration,
            hlil_file,
            pseudoc_file,
            mlil_file,
            mlil_ssa_file,
            llil_file,
            "; ".join(function_errors),
            memory_window=memory_window,
        ),
    )


def _record_session_memory_ceiling(session: ExportSession) -> None:
    memory_window = _end_memory_window(session)
    session.failures.append(
        _failure_record(
            None,
            None,
            "memory",
            "Process PrivateUsage reached the configured memory ceiling",
            reason="memory-ceiling",
            memory_window=memory_window,
        )
    )
    session.stop_requested = True


def stop_for_memory_ceiling(session: ExportSession) -> bool:
    if session.stop_requested:
        return True
    if not _memory_ceiling_reached(session):
        return False
    _record_session_memory_ceiling(session)
    return True


def _export_global_records(session: ExportSession, bv: object) -> None:
    cfg = session.cfg
    paths = session.paths
    begin_memory_window(session)
    if stop_for_memory_ceiling(session):
        return

    if cfg.export_sections:
        try:
            write_json(paths.sections_path, collect_section_records(bv))
        except Exception as exc:
            session.failures.append(_failure_record(None, None, "sections", exc))
        if stop_for_memory_ceiling(session):
            return

    if cfg.export_segments:
        try:
            write_json(paths.segments_path, collect_segment_records(bv))
        except Exception as exc:
            session.failures.append(_failure_record(None, None, "segments", exc))
        if stop_for_memory_ceiling(session):
            return

    if cfg.export_strings:
        try:
            string_records = collect_string_records(bv)
            write_jsonl_records(paths.strings_path, string_records)
            session.strings_exported = len(string_records)
        except Exception as exc:
            session.failures.append(_failure_record(None, None, "strings", exc))
        if stop_for_memory_ceiling(session):
            return

    if cfg.export_data_vars:
        try:
            data_var_records = collect_data_var_records(bv)
            write_jsonl_records(paths.data_vars_path, data_var_records)
            session.data_vars_exported = len(data_var_records)
        except Exception as exc:
            session.failures.append(_failure_record(None, None, "data_vars", exc))
        if stop_for_memory_ceiling(session):
            return

    if cfg.export_symbols:
        try:
            symbol_records = collect_symbol_records(bv)
            write_jsonl_records(paths.symbols_path, symbol_records)
            session.symbols_exported = len(symbol_records)
        except Exception as exc:
            session.failures.append(_failure_record(None, None, "symbols", exc))
        if stop_for_memory_ceiling(session):
            return

    _end_memory_window(session)


def _resolve_one_function(bv: object, function_key: FunctionKey) -> object | None:
    resolved = resolve_recognized_functions(bv, [function_key])
    return resolved[0] if resolved else None


def _export_hlil_family_for_function(
    session: ExportSession,
    bv: object,
    func: object,
    declaration: str | None,
    deadline: float,
    is_cancelled: Callable[[], bool] | None,
) -> tuple[str | None, str | None, list[str], bool]:
    hlil_file: str | None = None
    pseudoc_file: str | None = None
    errors: list[str] = []
    cfg = session.cfg

    if not (cfg.export_hlil or cfg.export_pseudoc):
        return hlil_file, pseudoc_file, errors, False
    if _export_cancelled(is_cancelled) or _export_timed_out(deadline) or _memory_ceiling_reached(session):
        return hlil_file, pseudoc_file, errors, True

    name, _, _ = function_identity(func)
    stem = function_file_stem(name)
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
            if _export_cancelled(is_cancelled) or _export_timed_out(deadline) or _memory_ceiling_reached(session):
                return hlil_file, pseudoc_file, errors, True
        if cfg.export_pseudoc:
            try:
                pseudoc_file = f"{stem}.pseudoc.c"
                write_text(session.paths.pseudoc_dir / pseudoc_file, render_pseudoc(hlil, declaration))
                session.pseudoc_exported += 1
            except Exception as exc:
                _record_function_error(errors, "pseudoc", exc)
                session.failures.append(_failure_record(func.start, name, "pseudoc", exc))
            if _export_cancelled(is_cancelled) or _export_timed_out(deadline) or _memory_ceiling_reached(session):
                return hlil_file, pseudoc_file, errors, True
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

    return (
        hlil_file,
        pseudoc_file,
        errors,
        _export_cancelled(is_cancelled) or _export_timed_out(deadline) or _memory_ceiling_reached(session),
    )


def _export_mlil_family_for_function(
    session: ExportSession, bv: object, func: object, deadline: float, is_cancelled: Callable[[], bool] | None
) -> tuple[str | None, str | None, list[str], bool]:
    mlil_file: str | None = None
    mlil_ssa_file: str | None = None
    errors: list[str] = []
    cfg = session.cfg

    if not (cfg.export_mlil or cfg.export_mlil_ssa):
        return mlil_file, mlil_ssa_file, errors, False
    if _export_cancelled(is_cancelled) or _export_timed_out(deadline) or _memory_ceiling_reached(session):
        return mlil_file, mlil_ssa_file, errors, True

    name, _, _ = function_identity(func)
    stem = function_file_stem(name)
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
            if _export_cancelled(is_cancelled) or _export_timed_out(deadline) or _memory_ceiling_reached(session):
                return mlil_file, mlil_ssa_file, errors, True
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
            if _export_cancelled(is_cancelled) or _export_timed_out(deadline) or _memory_ceiling_reached(session):
                return mlil_file, mlil_ssa_file, errors, True
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

    return (
        mlil_file,
        mlil_ssa_file,
        errors,
        _export_cancelled(is_cancelled) or _export_timed_out(deadline) or _memory_ceiling_reached(session),
    )


def _export_llil_for_function(
    session: ExportSession, func: object, deadline: float, is_cancelled: Callable[[], bool] | None
) -> tuple[str | None, list[str], bool]:
    llil_file: str | None = None
    errors: list[str] = []
    if not session.cfg.export_llil:
        return llil_file, errors, False
    if _export_cancelled(is_cancelled) or _export_timed_out(deadline) or _memory_ceiling_reached(session):
        return llil_file, errors, True

    name, _, _ = function_identity(func)
    stem = function_file_stem(name)
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
    return (
        llil_file,
        errors,
        _export_cancelled(is_cancelled) or _export_timed_out(deadline) or _memory_ceiling_reached(session),
    )


def prepare_export_session(bv: object, cfg: ExportConfig, function_keys: list[FunctionKey]) -> ExportSession:
    paths = ExportPaths.from_root(Path(cfg.output_dir))
    reused_records = _load_reused_index_records(paths, bv, cfg, function_keys) if cfg.incremental else []
    prepare_output_tree(paths, cfg.overwrite, reuse_existing=cfg.incremental)
    if cfg.incremental:
        _clear_incremental_global_records(paths)
    memory_monitor = ProcessMemoryMonitor(cfg.private_memory_limit_gib * 1024**3)
    memory_monitor.start()
    try:
        session = ExportSession(cfg=cfg, paths=paths, function_keys=function_keys, memory_monitor=memory_monitor)
        _restore_reused_records(session, reused_records)
        write_json(paths.export_config_path, cfg.to_dict())
        write_json(paths.binary_meta_path, collect_binary_metadata(bv, len(function_keys)))
        return session
    except Exception:
        memory_monitor.stop()
        raise


def export_function(
    session: ExportSession,
    bv: object,
    function_key: FunctionKey,
    is_cancelled: Callable[[], bool] | None = None,
) -> None:
    start, _ = function_key
    if session.stop_requested or start in session.indexed_starts:
        return
    begin_memory_window(session)
    func = _resolve_one_function(bv, function_key)
    if func is None:
        error = "Function disappeared before export"
        memory_window = _end_memory_window(session)
        session.failures.append(_failure_record(start, None, "resolve", error, memory_window=memory_window))
        _append_index_record(session, start, _failed_index_record(start, None, error, memory_window=memory_window))
        return
    if getattr(func, "needs_update", False):
        name, _, _ = function_identity(func)
        error = "Function still needs analysis update"
        memory_window = _end_memory_window(session)
        session.failures.append(
            _failure_record(int(getattr(func, "start", start)), name, "analysis", error, memory_window=memory_window)
        )
        _append_index_record(session, start, _failed_index_record(start, name, error, memory_window=memory_window))
        return

    name, _, _ = function_identity(func)
    started_at = monotonic()
    deadline = started_at + session.cfg.function_time_limit_seconds
    declaration: str | None = None
    hlil_file: str | None = None
    pseudoc_file: str | None = None
    mlil_file: str | None = None
    mlil_ssa_file: str | None = None
    llil_file: str | None = None
    function_errors: list[str] = []

    def record_timeout() -> None:
        _record_export_timeout(
            session,
            func,
            start,
            name,
            declaration,
            hlil_file,
            pseudoc_file,
            mlil_file,
            mlil_ssa_file,
            llil_file,
            function_errors,
            started_at,
        )

    def record_memory_ceiling() -> None:
        _record_memory_ceiling(
            session,
            func,
            start,
            name,
            declaration,
            hlil_file,
            pseudoc_file,
            mlil_file,
            mlil_ssa_file,
            llil_file,
            function_errors,
            started_at,
        )

    def record_cancellation() -> None:
        _record_export_cancelled(
            session,
            start,
            name,
            declaration,
            hlil_file,
            pseudoc_file,
            mlil_file,
            mlil_ssa_file,
            llil_file,
            function_errors,
            started_at,
        )

    def should_stop_at_boundary() -> bool:
        if _export_cancelled(is_cancelled):
            record_cancellation()
            return True
        if _memory_ceiling_reached(session):
            record_memory_ceiling()
            return True
        if _export_timed_out(deadline):
            record_timeout()
            return True
        return False

    try:
        if should_stop_at_boundary():
            return
        declaration = function_declaration(func)
        if should_stop_at_boundary():
            return
        hlil_file, pseudoc_file, hlil_errors, _ = _export_hlil_family_for_function(
            session, bv, func, declaration, deadline, is_cancelled
        )
        function_errors.extend(hlil_errors)
        if should_stop_at_boundary():
            return
        mlil_file, mlil_ssa_file, mlil_errors, _ = _export_mlil_family_for_function(
            session, bv, func, deadline, is_cancelled
        )
        function_errors.extend(mlil_errors)
        if should_stop_at_boundary():
            return
        llil_file, llil_errors, _ = _export_llil_for_function(session, func, deadline, is_cancelled)
        function_errors.extend(llil_errors)
        if should_stop_at_boundary():
            return
        call_evidence = collect_call_evidence(bv, func)
        if should_stop_at_boundary():
            return
        meta = build_function_meta(
            func,
            hlil_file=hlil_file,
            pseudoc_file=pseudoc_file,
            mlil_file=mlil_file,
            mlil_ssa_file=mlil_ssa_file,
            llil_file=llil_file,
            declaration=declaration,
            call_evidence=call_evidence,
            export_error="; ".join(function_errors) if function_errors else None,
        )
        if should_stop_at_boundary():
            return
        meta_name = f"{function_file_stem(name)}.meta.json"
        write_json(session.paths.functions_dir / meta_name, meta.to_dict())
        if should_stop_at_boundary():
            return
        memory_window = _end_memory_window(session)
        index_record = meta.to_index_record(meta_name)
        if memory_window is not None:
            index_record["memory_window"] = memory_window
        _append_index_record(session, start, index_record)
        session.meta_exported += 1
        if not function_errors:
            session.exported_function_count += 1
    except Exception as exc:
        memory_window = _end_memory_window(session)
        session.failures.append(_failure_record(func.start, name, "function", exc, memory_window=memory_window))
        _append_index_record(session, start, _failed_index_record(start, name, exc, memory_window=memory_window))


def _ensure_index_records(session: ExportSession) -> None:
    status = "not_exported" if session.cancelled else "failed"
    message = "Export cancelled before this function" if session.cancelled else "Function was not exported"
    for start, _ in session.function_keys:
        _append_index_record(session, start, _failed_index_record(start, None, message, status))


def _snapshot_status(session: ExportSession) -> str:
    if session.cancelled:
        return "cancelled"
    if session.exported_function_count == len(session.function_keys) and not session.failures:
        return "complete"
    return "partial"


def _failed_function_count(session: ExportSession) -> int:
    return sum(record.get("export_status") in {"failed", "partial"} for record in session.index_records)


def _apply_startup_stages(session: ExportSession, entries: list[dict[str, str]]) -> None:
    stages_by_id: dict[str, list[str]] = {}
    for entry in entries:
        stages_by_id.setdefault(entry["id"], []).append(entry["stage"])
    for record in session.index_records:
        record["startup_stages"] = list(dict.fromkeys(stages_by_id.get(str(record["id"]), [])))


def finalize_export_session(session: ExportSession, bv: object) -> ExportSummary:
    try:
        return _finalize_export_session(session, bv)
    finally:
        _end_memory_window(session)
        if session.memory_monitor is not None:
            session.memory_monitor.stop()


def _finalize_export_session(session: ExportSession, bv: object) -> ExportSummary:
    if not session.cancelled and not session.stop_requested:
        _export_global_records(session, bv)
    _ensure_index_records(session)
    if session.stop_requested:
        startup = {"target_kind": "unknown", "entries": []}
    else:
        try:
            startup = collect_startup_entries(bv, {key[0] for key in session.function_keys})
        except Exception as exc:
            session.failures.append(_failure_record(None, None, "startup", exc))
            startup = {"target_kind": "unknown", "entries": []}
    entries = startup["entries"]
    _apply_startup_stages(session, entries)
    write_json(session.paths.startup_entries_path, startup)
    write_jsonl_records(session.paths.function_index_path, session.index_records)
    if session.cfg.write_failures:
        write_jsonl_records(session.paths.failures_path, session.failures)

    status = _snapshot_status(session)
    write_json(
        session.paths.binary_meta_path,
        collect_binary_metadata(
            bv,
            len(session.function_keys),
            snapshot_status=status,
            exported_function_count=session.exported_function_count,
            failed_function_count=_failed_function_count(session),
        ),
    )

    return ExportSummary(
        status=status,
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
        if function_key[0] in session.indexed_starts:
            continue
        export_function(session, bv, function_key)
        if session.cancelled:
            break
    return finalize_export_session(session, bv)
