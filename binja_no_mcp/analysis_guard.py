from __future__ import annotations

from dataclasses import dataclass
from time import monotonic, sleep
from typing import Callable, Final

from binaryninja.enums import AnalysisSkipReason, SettingsScope
from binaryninja.function import Function
from binaryninja.settings import Settings


ANALYSIS_TIME_LIMIT_SETTING: Final = "analysis.limits.maxFunctionAnalysisTime"
WORKFLOW_POLL_INTERVAL_SECONDS: Final = 0.1


@dataclass(frozen=True, slots=True)
class FunctionAnalysisSettingsSnapshot:
    """The function-scoped settings to restore after one export reanalysis."""

    function: Function
    contents: str
    reanalysis_requested_at: float
    post_request_work_observed: bool


@dataclass(frozen=True, slots=True)
class FunctionAnalysisResult:
    """The observable outcome of waiting for a function workflow."""

    completed: bool
    reason: str | None
    elapsed_seconds: float


def start_function_reanalysis(function: Function, time_limit_seconds: int) -> FunctionAnalysisSettingsSnapshot:
    """Apply a temporary function budget and request reanalysis from the main thread."""

    settings = Settings()
    scope = SettingsScope.SettingsResourceScope
    contents = settings.serialize_settings(function, scope)
    if not settings.set_integer(ANALYSIS_TIME_LIMIT_SETTING, time_limit_seconds * 1000, function, scope):
        raise RuntimeError("Unable to set the function analysis time limit")
    snapshot = FunctionAnalysisSettingsSnapshot(function, contents, monotonic(), False)
    try:
        if function.analysis_skipped:
            function.analysis_skipped = False
        function.reanalyze()
        return FunctionAnalysisSettingsSnapshot(
            function,
            contents,
            snapshot.reanalysis_requested_at,
            function.needs_update,
        )
    except Exception:
        restore_function_analysis_settings(snapshot)
        raise


def restore_function_analysis_settings(snapshot: FunctionAnalysisSettingsSnapshot) -> None:
    """Restore the exact function-scoped settings present before export reanalysis."""

    settings = Settings()
    scope = SettingsScope.SettingsResourceScope
    if not settings.reset(ANALYSIS_TIME_LIMIT_SETTING, snapshot.function, scope):
        raise RuntimeError("Unable to reset the function analysis time limit")
    if not settings.deserialize_settings(snapshot.contents, snapshot.function, scope):
        raise RuntimeError("Unable to restore the function analysis settings")


def _workflow_state(function: Function) -> str | None:
    workflow = function.workflow
    if workflow is None:
        return None
    status = workflow.machine.status()
    if not isinstance(status, dict):
        return None
    command_status = status.get("commandStatus")
    if isinstance(command_status, dict) and command_status.get("accepted") is False:
        return None
    machine_state = status.get("machineState")
    if not isinstance(machine_state, dict):
        return None
    state = machine_state.get("state")
    return state if isinstance(state, str) else None


def wait_for_function_workflow(
    function: Function,
    time_limit_seconds: int,
    is_cancelled: Callable[[], bool],
    on_progress: Callable[[float], None] | None = None,
    is_skip_requested: Callable[[], bool] | None = None,
    reanalysis_requested_at: float | None = None,
    post_request_work_observed: bool = False,
    is_memory_ceiling_reached: Callable[[], bool] | None = None,
    on_memory_ceiling: Callable[[], None] | None = None,
) -> FunctionAnalysisResult:
    """Wait cooperatively until the reanalysis workflow is confirmed complete or noncomplete."""

    started_at = monotonic() if reanalysis_requested_at is None else reanalysis_requested_at
    saw_work_pending = post_request_work_observed
    memory_ceiling_seen = False
    while True:
        elapsed_seconds = monotonic() - started_at
        if on_progress is not None:
            on_progress(elapsed_seconds)
        if is_cancelled():
            return FunctionAnalysisResult(False, "cancelled", elapsed_seconds)
        if is_memory_ceiling_reached is not None and is_memory_ceiling_reached() and not memory_ceiling_seen:
            memory_ceiling_seen = True
            if on_memory_ceiling is not None:
                on_memory_ceiling()
        if function.analysis_skipped:
            if memory_ceiling_seen:
                return FunctionAnalysisResult(False, "memory-ceiling", elapsed_seconds)
            reason = (
                "analysis-deferred"
                if function.analysis_skip_reason == AnalysisSkipReason.ExceedFunctionAnalysisTimeSkipReason
                else "analysis-unconfirmed"
            )
            return FunctionAnalysisResult(False, reason, elapsed_seconds)
        state = _workflow_state(function)
        if state is None:
            if memory_ceiling_seen:
                return FunctionAnalysisResult(False, "memory-ceiling", elapsed_seconds)
            return FunctionAnalysisResult(False, "analysis-unconfirmed", elapsed_seconds)
        if state != "Idle" or function.needs_update:
            saw_work_pending = True
        if memory_ceiling_seen and state in {"Idle", "Halted", "Suspend", "Suspended"}:
            return FunctionAnalysisResult(False, "memory-ceiling", elapsed_seconds)
        if is_skip_requested is not None and is_skip_requested() and state in {"Idle", "Halted", "Suspend", "Suspended"}:
            return FunctionAnalysisResult(False, "skipped", elapsed_seconds)
        if state == "Idle" and not function.needs_update:
            if saw_work_pending:
                return FunctionAnalysisResult(True, None, elapsed_seconds)
            return FunctionAnalysisResult(False, "analysis-unconfirmed", elapsed_seconds)
        if elapsed_seconds >= time_limit_seconds:
            if memory_ceiling_seen:
                return FunctionAnalysisResult(False, "memory-ceiling", elapsed_seconds)
            return FunctionAnalysisResult(False, "analysis-unconfirmed", elapsed_seconds)
        sleep(WORKFLOW_POLL_INTERVAL_SECONDS)
