from __future__ import annotations

from pathlib import Path

from binaryninja import MessageBoxButtonSet, MessageBoxIcon, PluginCommand, log_error
from binaryninja.interaction import CheckboxField, DirectoryNameField, get_form_input, show_message_box
from binaryninja.mainthread import execute_on_main_thread
from binaryninja.plugin import BackgroundTask

from .collectors import freeze_recognized_function_keys, resolve_recognized_functions
from .config import ExportConfig
from .export_runner import export_function, finalize_export_session, prepare_export_session, run_export

PLUGIN_COMMAND_NAME = "Export for AI"
PLUGIN_COMMAND_DESCRIPTION = "Export recognized functions, IL, and metadata for AI IDEs"
_PLUGIN_REGISTERED = False
_PENDING_EXPORT_EVENTS: list[object] = []


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

    task = BackgroundTask("Preparing export for AI", False)

    if not cfg.reanalyze_before_export:
        try:
            summary = run_export(bv, cfg, function_keys=function_keys)
        except Exception as exc:
            task.finish()
            log_error(f"Binja-NO-MCP export failed: {exc}")
            _show_failure(exc)
            return
        task.finish()
        _show_completion(summary)
        return

    try:
        session = prepare_export_session(bv, cfg, function_keys)
    except Exception as exc:
        task.finish()
        log_error(f"Binja-NO-MCP export failed before scheduling: {exc}")
        _show_failure(exc)
        return

    state = {"index": 0, "retry_count": 0}

    def schedule_next_reanalysis() -> None:
        index = state["index"]
        if index >= len(function_keys):
            summary = finalize_export_session(session, bv)
            task.finish()
            execute_on_main_thread(lambda summary=summary: _show_completion(summary))
            if event in _PENDING_EXPORT_EVENTS:
                _PENDING_EXPORT_EVENTS.remove(event)
            return

        function_key = function_keys[index]
        task.progress = f"Reanalyzing function {index + 1}/{len(function_keys)}"
        _request_function_reanalysis(bv, [function_key])
        bv.update_analysis()

    def completion_callback() -> None:
        try:
            index = state["index"]
            if index >= len(function_keys):
                return

            function_key = function_keys[index]
            func = resolve_recognized_functions(bv, [function_key])
            if func and getattr(func[0], "needs_update", False) and state["retry_count"] < 3:
                state["retry_count"] += 1
                task.progress = f"Waiting for function {index + 1}/{len(function_keys)} analysis to settle"
                bv.update_analysis()
                return

            task.progress = f"Exporting function {index + 1}/{len(function_keys)}"
            export_function(session, bv, function_key)
            state["index"] += 1
            state["retry_count"] = 0
            schedule_next_reanalysis()
        except Exception as exc:
            log_error(f"Binja-NO-MCP export failed: {exc}")
            execute_on_main_thread(lambda exc=exc: _show_failure(exc))
            task.finish()
            if event in _PENDING_EXPORT_EVENTS:
                _PENDING_EXPORT_EVENTS.remove(event)
            return

    event = bv.add_analysis_completion_event(completion_callback)
    _PENDING_EXPORT_EVENTS.append(event)

    try:
        schedule_next_reanalysis()
    except Exception as exc:
        task.finish()
        if event in _PENDING_EXPORT_EVENTS:
            _PENDING_EXPORT_EVENTS.remove(event)
        log_error(f"Binja-NO-MCP export failed before scheduling: {exc}")
        _show_failure(exc)


def register_plugin() -> None:
    global _PLUGIN_REGISTERED
    if _PLUGIN_REGISTERED:
        return
    PluginCommand.register(PLUGIN_COMMAND_NAME, PLUGIN_COMMAND_DESCRIPTION, export_for_ai)
    _PLUGIN_REGISTERED = True
