from __future__ import annotations

from pathlib import Path
from threading import Lock

from binaryninja import MessageBoxButtonResult, MessageBoxButtonSet, MessageBoxIcon, PluginCommand, log_error
from binaryninja.interaction import CheckboxField, DirectoryNameField, IntegerField, get_form_input, show_message_box
from binaryninja.mainthread import execute_on_main_thread, execute_on_main_thread_and_wait
from binaryninja.plugin import BackgroundTaskThread

from .collectors import freeze_recognized_function_keys, resolve_recognized_functions
from .config import ExportConfig
from .export_runner import (
    begin_memory_window,
    export_function,
    finalize_export_session,
    prepare_export_session,
    record_function_analysis_cancelled,
    record_function_analysis_failure,
    record_function_memory_ceiling,
    run_export,
    stop_for_memory_ceiling,
)
from .naming import function_id
from . import analysis_guard

PLUGIN_COMMAND_NAME = "Export for AI"
PLUGIN_COMMAND_DESCRIPTION = "Export recognized functions, IL, and metadata for AI IDEs"
SKIP_CURRENT_FUNCTION_COMMAND_NAME = "Export for AI\\Skip Current Function"
SKIP_CURRENT_FUNCTION_COMMAND_DESCRIPTION = "Request a cooperative halt for the function currently being reanalyzed"
ABORT_BINARY_VIEW_ANALYSIS_COMMAND_NAME = "Export for AI\\Abort BinaryView Analysis"
ABORT_BINARY_VIEW_ANALYSIS_COMMAND_DESCRIPTION = "Abort analysis for this entire BinaryView after confirmation"
_PLUGIN_REGISTERED = False
_ACTIVE_TASKS: dict[int, object] = {}
_ACTIVE_TASKS_LOCK = Lock()
_TASK_CONTROL_LOCK = Lock()


def _register_active_task(bv: object, task: object) -> None:
    with _ACTIVE_TASKS_LOCK:
        _ACTIVE_TASKS[id(bv)] = task


def _unregister_active_task(bv: object, task: object) -> None:
    with _ACTIVE_TASKS_LOCK:
        if _ACTIVE_TASKS.get(id(bv)) is task:
            del _ACTIVE_TASKS[id(bv)]


def _active_task_for(bv: object) -> object | None:
    with _ACTIVE_TASKS_LOCK:
        return _ACTIVE_TASKS.get(id(bv))


def _set_current_function(task: object, function_key: tuple[int, str | None], func: object) -> None:
    with _TASK_CONTROL_LOCK:
        setattr(task, "_current_function_key", function_key)
        setattr(task, "_current_function", func)
        setattr(task, "_skip_requested_key", None)
        setattr(task, "_halt_pending_key", None)


def _finish_current_function(task: object, function_key: tuple[int, str | None]) -> bool:
    with _TASK_CONTROL_LOCK:
        skipped = getattr(task, "_skip_requested_key", None) == function_key
        if getattr(task, "_current_function_key", None) == function_key:
            setattr(task, "_current_function_key", None)
            setattr(task, "_current_function", None)
        if getattr(task, "_halt_pending_key", None) == function_key:
            setattr(task, "_halt_pending_key", None)
        if skipped:
            setattr(task, "_skip_requested_key", None)
        return skipped


def _skip_requested_for(task: object, function_key: tuple[int, str | None]) -> bool:
    with _TASK_CONTROL_LOCK:
        return getattr(task, "_skip_requested_key", None) == function_key


def _halt_function_workflow(func: object) -> bool:
    response = func.workflow.machine.halt()
    if not isinstance(response, dict):
        return True
    command_status = response.get("commandStatus")
    if isinstance(command_status, dict):
        return command_status.get("accepted") is not False
    return response.get("accepted") is not False


def _request_memory_ceiling_halt(task: object, function_key: tuple[int, str | None], func: object) -> None:
    def halt() -> None:
        with _TASK_CONTROL_LOCK:
            if (
                getattr(task, "_current_function_key", None) != function_key
                or getattr(task, "_current_function", None) is not func
            ):
                return
        try:
            if not _halt_function_workflow(func):
                log_error("Binja-NO-MCP function workflow halt was rejected after the memory ceiling was reached")
        except Exception as exc:
            log_error(f"Binja-NO-MCP could not request a memory-ceiling workflow halt: {exc}")

    execute_on_main_thread(halt)


def _skip_current_function(bv: object) -> None:
    task = _active_task_for(bv)
    if task is None:
        show_message_box(
            "Export for AI",
            "No function is currently waiting for workflow analysis.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.InformationIcon,
        )
        return

    with _TASK_CONTROL_LOCK:
        function_key = getattr(task, "_current_function_key", None)
        func = getattr(task, "_current_function", None)
        already_requested = (
            getattr(task, "_skip_requested_key", None) == function_key
            or getattr(task, "_halt_pending_key", None) == function_key
        )
        if function_key is not None and func is not None and not already_requested:
            setattr(task, "_halt_pending_key", function_key)

    if function_key is None or func is None:
        show_message_box(
            "Export for AI",
            "No function is currently waiting for workflow analysis.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.InformationIcon,
        )
        return
    if already_requested:
        return

    def halt() -> None:
        with _TASK_CONTROL_LOCK:
            if (
                getattr(task, "_current_function_key", None) != function_key
                or getattr(task, "_current_function", None) is not func
            ):
                if getattr(task, "_halt_pending_key", None) == function_key:
                    setattr(task, "_halt_pending_key", None)
                return
        try:
            accepted = _halt_function_workflow(func)
        except Exception as exc:
            log_error(f"Binja-NO-MCP could not request a function workflow halt: {exc}")
        else:
            if not accepted:
                log_error("Binja-NO-MCP function workflow halt request was rejected")
            else:
                with _TASK_CONTROL_LOCK:
                    if (
                        getattr(task, "_current_function_key", None) == function_key
                        and getattr(task, "_current_function", None) is func
                    ):
                        setattr(task, "_skip_requested_key", function_key)
        finally:
            with _TASK_CONTROL_LOCK:
                if getattr(task, "_halt_pending_key", None) == function_key:
                    setattr(task, "_halt_pending_key", None)

    execute_on_main_thread(halt)


def _abort_binary_view_analysis(bv: object) -> None:
    response = show_message_box(
        "Abort BinaryView Analysis",
        "Abort analysis for the entire BinaryView? This is not limited to the current export function.",
        MessageBoxButtonSet.YesNoButtonSet,
        MessageBoxIcon.WarningIcon,
    )
    if response != MessageBoxButtonResult.YesButton:
        return
    try:
        bv.abort_analysis()
    except Exception as exc:
        log_error(f"Binja-NO-MCP could not abort BinaryView analysis: {exc}")
        show_message_box(
            "Abort BinaryView Analysis",
            f"Could not abort BinaryView analysis:\n\n{exc}",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )


def _default_output_dir(bv: object) -> Path:
    filename = getattr(getattr(bv, "file", None), "filename", None)
    if filename:
        return Path(filename).expanduser().resolve().parent / "binja-no-mcp-export"
    return Path.cwd() / "binja-no-mcp-export"


def _prompt_export_config(bv: object) -> ExportConfig | None:
    output_dir = DirectoryNameField("Output directory", default_name=str(_default_output_dir(bv)))
    reanalyze_before_export = CheckboxField("Reanalyze frozen functions before export", True)
    function_time_limit_seconds = IntegerField("Function analysis/export time limit (seconds)", default=900)
    private_memory_limit_gib = IntegerField("Binary Ninja PrivateUsage limit (GiB)", default=24)
    export_hlil = CheckboxField("Export raw HLIL (.hlil.txt)", True)
    export_pseudoc = CheckboxField("Export pseudo-C (.pseudoc.c)", False)
    export_mlil = CheckboxField("Export MLIL (.mlil.txt)", False)
    export_mlil_ssa = CheckboxField("Export MLIL SSA (.mlil_ssa.txt)", False)
    export_llil = CheckboxField("Export LLIL (.llil.txt)", False)

    accepted = get_form_input(
        [
            "Select export target and IL formats",
            None,
            output_dir,
            None,
            reanalyze_before_export,
            function_time_limit_seconds,
            private_memory_limit_gib,
            None,
            "Optional IL exports",
            export_hlil,
            export_pseudoc,
            export_mlil,
            export_mlil_ssa,
            export_llil,
        ],
        "Export for AI",
    )
    if (
        not accepted
        or not output_dir.result
        or function_time_limit_seconds.result is None
        or private_memory_limit_gib.result is None
    ):
        return None
    if function_time_limit_seconds.result < 1:
        show_message_box(
            "Export for AI",
            "Function analysis/export time limit must be at least one second.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.WarningIcon,
        )
        return None
    if private_memory_limit_gib.result < 1:
        show_message_box(
            "Export for AI",
            "Binary Ninja PrivateUsage limit must be at least one GiB.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.WarningIcon,
        )
        return None

    return ExportConfig(
        output_dir=Path(output_dir.result),
        reanalyze_before_export=bool(reanalyze_before_export.result),
        function_time_limit_seconds=int(function_time_limit_seconds.result),
        private_memory_limit_gib=int(private_memory_limit_gib.result),
        export_hlil=bool(export_hlil.result),
        export_pseudoc=bool(export_pseudoc.result),
        export_mlil=bool(export_mlil.result),
        export_mlil_ssa=bool(export_mlil_ssa.result),
        export_llil=bool(export_llil.result),
    )


def _show_completion(summary: object) -> None:
    status_text = {
        "complete": "Export completed.",
        "partial": "Export partially completed.",
        "cancelled": "Export cancelled.",
    }.get(getattr(summary, "status", None), "Export completed.")
    show_message_box(
        "Export for AI",
        (
            f"{status_text}\n\n"
            f"Output: {summary.output_dir}\n"
            f"Functions: {summary.function_count}\n"
            f"HLIL: {summary.hlil_exported}\n"
            f"Pseudo-C: {summary.pseudoc_exported}\n"
            f"MLIL: {summary.mlil_exported}\n"
            f"MLIL SSA: {summary.mlil_ssa_exported}\n"
            f"LLIL: {summary.llil_exported}\n"
            f"Failures: {summary.failures}"
        ),
        MessageBoxButtonSet.OKButtonSet,
        MessageBoxIcon.InformationIcon,
    )


def _show_failure(exc: Exception) -> None:
    show_message_box(
        "Export for AI",
        f"Export failed:\n\n{exc}",
        MessageBoxButtonSet.OKButtonSet,
        MessageBoxIcon.ErrorIcon,
    )


def _start_function_reanalysis(
    bv: object,
    function_key: tuple[int, str | None],
    time_limit_seconds: int,
) -> tuple[object, analysis_guard.FunctionAnalysisSettingsSnapshot] | None:
    functions = resolve_recognized_functions(bv, [function_key])
    if not functions:
        return None
    func = functions[0]
    return func, analysis_guard.start_function_reanalysis(func, time_limit_seconds)


def _function_progress_label(bv: object, function_key: tuple[int, str | None]) -> str:
    for function in resolve_recognized_functions(bv, [function_key]):
        symbol = getattr(function, "symbol", None)
        if getattr(symbol, "auto", False):
            return function_id(function_key[0])
        for value in (
            getattr(function, "name", None),
            getattr(symbol, "raw_name", None),
        ):
            if value:
                return str(value)
    return function_id(function_key[0])


def _progress_text(
    stage: str,
    index: int,
    total: int,
    label: str,
    cfg: ExportConfig,
    elapsed_seconds: float = 0.0,
) -> str:
    return (
        f"{stage} function {index}/{total}: {label} "
        f"· {elapsed_seconds:.0f}s / {cfg.function_time_limit_seconds}s "
        f"· {cfg.private_memory_limit_gib} GiB"
    )


def _terminal_progress(status: str) -> str:
    return {
        "complete": "Export complete",
        "partial": "Export partial",
        "cancelled": "Export cancelled",
    }.get(status, "Export failed")


class _ExportTask(BackgroundTaskThread):
    def __init__(self, bv: object, cfg: ExportConfig, function_keys: list[tuple[int, str | None]]) -> None:
        super().__init__("Preparing export for AI", True)
        self._bv = bv
        self._cfg = cfg
        self._function_keys = function_keys
        self._function_labels: dict[tuple[int, str | None], str] = {}

    def run(self) -> None:
        session = None
        try:
            session = prepare_export_session(self._bv, self._cfg, self._function_keys)
            total = len(self._function_keys)

            for index, function_key in enumerate(self._function_keys, start=1):
                if self.cancelled:
                    session.cancelled = True
                    break
                if stop_for_memory_ceiling(session):
                    break

                label = self._function_labels.get(function_key)
                if label is None:
                    label = _function_progress_label(self._bv, function_key)
                    self._function_labels[function_key] = label

                if self._cfg.reanalyze_before_export:
                    begin_memory_window(session)
                    self.progress = _progress_text("Reanalyzing", index, total, label, self._cfg)
                    reanalysis: list[tuple[object, analysis_guard.FunctionAnalysisSettingsSnapshot]] = []

                    def start_reanalysis() -> None:
                        started = _start_function_reanalysis(
                            self._bv,
                            function_key,
                            self._cfg.function_time_limit_seconds,
                        )
                        if started is not None:
                            reanalysis.append(started)

                    execute_on_main_thread_and_wait(start_reanalysis)
                    if reanalysis:
                        func, snapshot = reanalysis[0]
                        _set_current_function(self, function_key, func)
                        last_elapsed_second = -1

                        def update_analysis_progress(elapsed_seconds: float) -> None:
                            nonlocal last_elapsed_second
                            elapsed_second = int(elapsed_seconds)
                            if elapsed_second == last_elapsed_second:
                                return
                            last_elapsed_second = elapsed_second
                            self.progress = _progress_text(
                                "Waiting for analysis",
                                index,
                                total,
                                label,
                                self._cfg,
                                elapsed_seconds,
                            )

                        try:
                            analysis_result = analysis_guard.wait_for_function_workflow(
                                func,
                                self._cfg.function_time_limit_seconds,
                                lambda: self.cancelled,
                                on_progress=update_analysis_progress,
                                is_skip_requested=lambda: _skip_requested_for(self, function_key),
                                reanalysis_requested_at=getattr(snapshot, "reanalysis_requested_at", None),
                                post_request_work_observed=getattr(snapshot, "post_request_work_observed", False),
                                is_memory_ceiling_reached=lambda: (
                                    session.memory_monitor is not None and session.memory_monitor.exceeded
                                ),
                                on_memory_ceiling=lambda: _request_memory_ceiling_halt(self, function_key, func),
                            )
                        finally:
                            execute_on_main_thread_and_wait(
                                lambda snapshot=snapshot: analysis_guard.restore_function_analysis_settings(snapshot)
                            )
                            _finish_current_function(self, function_key)
                        if analysis_result.reason == "cancelled" or self.cancelled:
                            record_function_analysis_cancelled(
                                session,
                                function_key,
                                func,
                                analysis_result.elapsed_seconds,
                            )
                            session.cancelled = True
                            break
                        if analysis_result.reason == "memory-ceiling" or (
                            session.memory_monitor is not None and session.memory_monitor.exceeded
                        ):
                            record_function_memory_ceiling(
                                session,
                                function_key,
                                func,
                                analysis_result.elapsed_seconds,
                            )
                            break
                        if analysis_result.reason == "skipped":
                            record_function_analysis_failure(
                                session,
                                function_key,
                                func,
                                "skipped",
                                analysis_result.elapsed_seconds,
                            )
                            continue
                        if not analysis_result.completed:
                            record_function_analysis_failure(
                                session,
                                function_key,
                                func,
                                str(analysis_result.reason),
                                analysis_result.elapsed_seconds,
                            )
                            continue

                if self.cancelled:
                    session.cancelled = True
                    break
                self.progress = _progress_text("Exporting", index, total, label, self._cfg)
                export_function(session, self._bv, function_key, lambda: self.cancelled)
                if session.stop_requested or session.cancelled:
                    break

            if self.cancelled:
                session.cancelled = True
            summary = finalize_export_session(session, self._bv)
            self.progress = _terminal_progress(summary.status)
            execute_on_main_thread(lambda summary=summary: _show_completion(summary))
        except Exception as exc:
            if session is not None:
                session.failures.append({"start": None, "name": None, "phase": "task", "error": str(exc)})
                try:
                    finalize_export_session(session, self._bv)
                except Exception as finalize_exc:
                    log_error(f"Binja-NO-MCP could not finalize failed export: {finalize_exc}")
            self.progress = "Export failed"
            log_error(f"Binja-NO-MCP export failed: {exc}")
            execute_on_main_thread(lambda exc=exc: _show_failure(exc))
        finally:
            _unregister_active_task(self._bv, self)


def export_for_ai(bv: object) -> None:
    cfg = _prompt_export_config(bv)
    if cfg is None:
        return

    function_keys = freeze_recognized_function_keys(bv)
    if not function_keys:
        show_message_box(
            "Export for AI",
            "No recognized functions are available for export.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.InformationIcon,
        )
        return

    if not cfg.reanalyze_before_export:
        try:
            summary = run_export(bv, cfg, function_keys=function_keys)
        except Exception as exc:
            log_error(f"Binja-NO-MCP export failed: {exc}")
            _show_failure(exc)
            return
        _show_completion(summary)
        return

    task = _ExportTask(bv, cfg, function_keys)
    _register_active_task(bv, task)
    try:
        task.start()
    except Exception:
        _unregister_active_task(bv, task)
        raise


def register_plugin() -> None:
    global _PLUGIN_REGISTERED
    if _PLUGIN_REGISTERED:
        return
    PluginCommand.register(PLUGIN_COMMAND_NAME, PLUGIN_COMMAND_DESCRIPTION, export_for_ai)
    PluginCommand.register(
        SKIP_CURRENT_FUNCTION_COMMAND_NAME,
        SKIP_CURRENT_FUNCTION_COMMAND_DESCRIPTION,
        _skip_current_function,
    )
    PluginCommand.register(
        ABORT_BINARY_VIEW_ANALYSIS_COMMAND_NAME,
        ABORT_BINARY_VIEW_ANALYSIS_COMMAND_DESCRIPTION,
        _abort_binary_view_analysis,
    )
    _PLUGIN_REGISTERED = True
