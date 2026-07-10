from __future__ import annotations

from pathlib import Path

from binaryninja import MessageBoxButtonSet, MessageBoxIcon, PluginCommand, log_error
from binaryninja.interaction import CheckboxField, DirectoryNameField, get_form_input, show_message_box
from binaryninja.mainthread import execute_on_main_thread, execute_on_main_thread_and_wait
from binaryninja.plugin import BackgroundTaskThread

from .collectors import freeze_recognized_function_keys, resolve_recognized_functions
from .config import ExportConfig
from .export_runner import export_function, finalize_export_session, prepare_export_session, run_export
from .naming import function_id

PLUGIN_COMMAND_NAME = "Export for AI"
PLUGIN_COMMAND_DESCRIPTION = "Export recognized functions, IL, and metadata for AI IDEs"
_PLUGIN_REGISTERED = False


def _default_output_dir(bv: object) -> Path:
    filename = getattr(getattr(bv, "file", None), "filename", None)
    if filename:
        return Path(filename).expanduser().resolve().parent / "binja-no-mcp-export"
    return Path.cwd() / "binja-no-mcp-export"


def _prompt_export_config(bv: object) -> ExportConfig | None:
    output_dir = DirectoryNameField("Output directory", default_name=str(_default_output_dir(bv)))
    reanalyze_before_export = CheckboxField("Reanalyze frozen functions before export", True)
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
    if not accepted or not output_dir.result:
        return None

    return ExportConfig(
        output_dir=Path(output_dir.result),
        reanalyze_before_export=bool(reanalyze_before_export.result),
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


def _request_function_reanalysis(bv: object, function_keys: list[tuple[int, str | None]]) -> None:
    for func in resolve_recognized_functions(bv, function_keys):
        if getattr(func, "analysis_skipped", False):
            func.analysis_skipped = False
        reanalyze = getattr(func, "reanalyze", None)
        if callable(reanalyze):
            reanalyze()


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


def _progress_text(stage: str, index: int, total: int, label: str) -> str:
    return f"{stage} function {index}/{total}: {label}"


def _terminal_progress(status: str) -> str:
    return {
        "complete": "Export complete",
        "partial": "Export partial",
        "cancelled": "Export cancelled",
    }.get(status, "Export failed")


class _ExportTask(BackgroundTaskThread):
    def __init__(self, bv: object, cfg: ExportConfig, function_keys: list[tuple[int, str | None]]) -> None:
        super().__init__("Preparing export for AI", False)
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

                label = self._function_labels.get(function_key)
                if label is None:
                    label = _function_progress_label(self._bv, function_key)
                    self._function_labels[function_key] = label

                if self._cfg.reanalyze_before_export:
                    self.progress = _progress_text("Reanalyzing", index, total, label)
                    execute_on_main_thread_and_wait(
                        lambda function_key=function_key: _request_function_reanalysis(self._bv, [function_key])
                    )
                    self.progress = _progress_text("Waiting for analysis", index, total, label)
                    self._bv.update_analysis_and_wait()

                if self.cancelled:
                    session.cancelled = True
                    break
                self.progress = _progress_text("Exporting", index, total, label)
                export_function(session, self._bv, function_key)

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
    task.start()


def register_plugin() -> None:
    global _PLUGIN_REGISTERED
    if _PLUGIN_REGISTERED:
        return
    PluginCommand.register(PLUGIN_COMMAND_NAME, PLUGIN_COMMAND_DESCRIPTION, export_for_ai)
    _PLUGIN_REGISTERED = True
