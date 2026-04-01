from __future__ import annotations

from pathlib import Path

from binaryninja import MessageBoxButtonSet, MessageBoxIcon, PluginCommand, log_error
from binaryninja.interaction import CheckboxField, DirectoryNameField, get_form_input, show_message_box
from binaryninja.mainthread import execute_on_main_thread, execute_on_main_thread_and_wait
from binaryninja.plugin import BackgroundTaskThread

from .collectors import freeze_recognized_function_keys, resolve_recognized_functions
from .config import ExportConfig
from .export_runner import export_function, finalize_export_session, prepare_export_session, run_export

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
    show_message_box(
        "Export for AI",
        (
            f"Export completed.\n\n"
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


class _ExportTask(BackgroundTaskThread):
    def __init__(self, bv: object, cfg: ExportConfig, function_keys: list[tuple[int, str | None]]) -> None:
        super().__init__("Preparing export for AI", False)
        self._bv = bv
        self._cfg = cfg
        self._function_keys = function_keys

    def run(self) -> None:
        try:
            session = prepare_export_session(self._bv, self._cfg, self._function_keys)
            total = len(self._function_keys)

            for index, function_key in enumerate(self._function_keys, start=1):
                if self.cancelled:
                    break

                if self._cfg.reanalyze_before_export:
                    self.progress = f"Reanalyzing function {index}/{total}"
                    execute_on_main_thread_and_wait(
                        lambda function_key=function_key: _request_function_reanalysis(self._bv, [function_key])
                    )
                    self.progress = f"Waiting for function {index}/{total} analysis to finish"
                    self._bv.update_analysis_and_wait()

                self.progress = f"Exporting function {index}/{total}"
                export_function(session, self._bv, function_key)

            summary = finalize_export_session(session, self._bv)
            execute_on_main_thread(lambda summary=summary: _show_completion(summary))
        except Exception as exc:
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
