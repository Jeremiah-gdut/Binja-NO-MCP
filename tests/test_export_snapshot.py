from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from binja_no_mcp import ExportConfig, run_export


class _Token:
    def __init__(self, text: str) -> None:
        self.text = text


class _Line:
    def __init__(self, text: str, address: int | None = None, mapped: bool = False) -> None:
        self.tokens = [_Token(text)]
        self.address = address
        self.il_instruction = object() if mapped else None


class _Root:
    def __init__(self, lines: list[_Line]) -> None:
        self._lines = lines

    def get_lines(self) -> list[_Line]:
        return self._lines


class _Il:
    def __init__(self, instructions: list[object] | None = None) -> None:
        self.instructions = instructions or []


class _Function:
    def __init__(
        self,
        start: int,
        name: str | None,
        *,
        needs_update: bool = False,
        llil: list[object] | None = None,
        mlil: list[object] | None = None,
    ) -> None:
        self.start = start
        self.name = name
        self.symbol = SimpleNamespace(raw_name=name, short_name=name) if name else None
        self.arch = SimpleNamespace(name="aarch64")
        self.needs_update = needs_update
        self.analysis_skipped = False
        self.type = None
        self.calling_convention = None
        self.can_return = None
        self.call_sites: list[object] = []
        self.low_level_il = _Il(llil)
        self.medium_level_il = _Il(mlil)
        self.reanalyzed = False

    def reanalyze(self) -> None:
        self.reanalyzed = True


class _RawView:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self, offset: int, length: int) -> bytes:
        return self._data[offset : offset + length]


class _BinaryView:
    def __init__(self, functions: list[_Function], raw: bytes, entry_point: int) -> None:
        self.functions = functions
        self.file = SimpleNamespace(filename="fixture.so", raw=_RawView(raw))
        self.arch = SimpleNamespace(name="aarch64")
        self.platform = None
        self.view_type = "ELF"
        self.start = 0
        self.end = len(raw)
        self.entry_point = entry_point
        self.sections = {}
        self.segments = []
        self.strings = []
        self.data_vars = {}
        self.symbols = {}

    def get_functions_at(self, start: int) -> list[_Function]:
        return [function for function in self.functions if function.start == start]

    def get_function_at(self, start: int) -> _Function | None:
        return next(iter(self.get_functions_at(start)), None)

    def hlil_functions(self, function_generator: object) -> object:
        for function in function_generator:
            yield SimpleNamespace(
                root=_Root(getattr(self, "linear_lines", [_Line("return;", function.start, mapped=True)])),
                source_function=function,
            )

    def get_callees(self, address: int, function: _Function, arch: object) -> list[int]:
        return list(getattr(function, "bn_callees", {}).get(address, []))

    def update_analysis_and_wait(self) -> None:
        pass


def _instruction(operation: str, address: int, target: int | None = None, params: list[object] | None = None) -> object:
    dest = SimpleNamespace(constant=target) if target is not None else SimpleNamespace()
    return SimpleNamespace(
        operation=SimpleNamespace(name=operation),
        address=address,
        dest=dest,
        params=params or [],
    )


def _elf64(
    *,
    elf_type: int,
    entry: int,
    dynamic_entries: list[tuple[int, int]],
    has_interp: bool = False,
) -> bytes:
    data = bytearray(0x800)
    program_headers = [(1, 0, 0, 0, len(data), len(data))]
    program_headers.append((2, 0x200, 0x200, 0, len(dynamic_entries + [(0, 0)]) * 16, 0))
    if has_interp:
        data[0x500:0x510] = b"/system/bin/linker\0"
        program_headers.append((3, 0x500, 0x500, 0, 0x10, 0))

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        data,
        0,
        ident,
        elf_type,
        183,
        1,
        entry,
        0x40,
        0,
        0,
        64,
        56,
        len(program_headers),
        0,
        0,
        0,
    )
    for index, (kind, offset, vaddr, flags, filesz, memsz) in enumerate(program_headers):
        struct.pack_into("<IIQQQQQQ", data, 0x40 + index * 56, kind, flags, offset, vaddr, 0, filesz, memsz, 8)
    for index, (tag, value) in enumerate([*dynamic_entries, (0, 0)]):
        struct.pack_into("<qQ", data, 0x200 + index * 16, tag, value)
    return bytes(data)


def _index(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in (path / "meta" / "function_index.jsonl").read_text(encoding="utf-8").splitlines()]


class ExportSnapshotTests(unittest.TestCase):
    def _executable_view(self, *, needs_update: bool = False) -> _BinaryView:
        bias = 0x100000
        raw = bytearray(
            _elf64(
                elf_type=2,
                entry=0x1000,
                dynamic_entries=[(32, 0x300), (33, 8), (12, 0x1200), (25, 0x320), (27, 8)],
            )
        )
        struct.pack_into("<Q", raw, 0x300, 0x1300)
        struct.pack_into("<Q", raw, 0x320, 0x1400)
        target = _Function(bias + 0x1200, "target")
        caller = _Function(
            bias + 0x1000,
            "main",
            needs_update=needs_update,
            llil=[
                _instruction("LLIL_CALL", bias + 0x1010, target.start),
                _instruction("LLIL_CALL", bias + 0x1020),
                _instruction("LLIL_CALL", bias + 0x1030, 0x1FFFF0),
            ],
        )
        caller.call_sites = [SimpleNamespace(address=bias + 0x1010, function=caller, arch=caller.arch)]
        caller.bn_callees = {bias + 0x1010: [target.start]}
        constructors = [_Function(bias + value, f"init_{value:x}") for value in (0x1300, 0x1400)]
        return _BinaryView([caller, target, *constructors], bytes(raw), caller.start)

    def _startup_route(self, bv: _BinaryView) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "snapshot"
            run_export(bv, ExportConfig(output_dir=output_dir))
            return json.loads((output_dir / "meta" / "startup_entries.json").read_text(encoding="utf-8"))

    def test_complete_snapshot_is_current_and_uses_stable_function_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "snapshot"
            bv = self._executable_view()
            summary = run_export(bv, ExportConfig(output_dir=output_dir))

            self.assertEqual(summary.status, "complete")
            header = json.loads((output_dir / "meta" / "binary.json").read_text(encoding="utf-8"))
            self.assertEqual(header["schema_version"], 1)
            self.assertEqual(header["snapshot_status"], "complete")
            self.assertEqual(header["planned_function_count"], 4)
            self.assertEqual(header["exported_function_count"], 4)
            self.assertEqual(header["failed_function_count"], 0)

            records = _index(output_dir)
            main = next(record for record in records if record["id"] == "0x101000")
            self.assertEqual(main["declaration"], None)
            self.assertEqual(main["export_status"], "exported")
            self.assertEqual(main["artifacts"]["hlil"], "functions/main.hlil.txt")
            self.assertIn("elf_entry", main["startup_stages"])
            self.assertIn("main", main["startup_stages"])
            self.assertNotIn("call_evidence", main)

            meta = json.loads((output_dir / "functions" / "main.meta.json").read_text(encoding="utf-8"))
            self.assertEqual(meta["id"], "0x101000")
            self.assertIn(
                {"source": "direct_il", "call_site": "0x101010", "target": "0x101200"},
                meta["call_evidence"],
            )
            self.assertIn(
                {"source": "unresolved_indirect", "call_site": "0x101020"},
                meta["call_evidence"],
            )
            self.assertIn(
                {"source": "direct_il", "call_site": "0x101030", "target": "0x1ffff0"},
                meta["call_evidence"],
            )
            self.assertIn(
                {"source": "bn_analysis", "call_site": "0x101010", "target": "0x101200"},
                meta["call_evidence"],
            )
            self.assertFalse(
                any(
                    evidence["source"] == "bn_analysis" and evidence["call_site"] == "0x101020"
                    for evidence in meta["call_evidence"]
                )
            )

            stale_file = output_dir / "functions" / "stale.txt"
            stale_file.write_text("old", encoding="utf-8")
            stale_optional = output_dir / "optional" / "stale.txt"
            stale_optional.parent.mkdir(parents=True, exist_ok=True)
            stale_optional.write_text("old", encoding="utf-8")
            bv.functions[0].name = "renamed_main"
            bv.functions[0].symbol = SimpleNamespace(raw_name="renamed_main", short_name="renamed_main")
            run_export(bv, ExportConfig(output_dir=output_dir))
            self.assertTrue((output_dir / "functions" / "renamed_main.hlil.txt").exists())
            self.assertFalse(stale_file.exists())
            self.assertFalse(stale_optional.exists())

    def test_function_failure_produces_a_partial_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "snapshot"
            bv = self._executable_view(needs_update=True)
            summary = run_export(bv, ExportConfig(output_dir=output_dir))
            self.assertEqual(summary.status, "partial")
            self.assertEqual(_index(output_dir)[0]["export_status"], "failed")
            header = json.loads((output_dir / "meta" / "binary.json").read_text(encoding="utf-8"))
            self.assertEqual(header["snapshot_status"], "partial")

    def test_startup_routes_are_conservative_for_shared_and_unknown_targets(self) -> None:
        pie_raw = bytearray(
            _elf64(
                elf_type=3,
                entry=0x1000,
                dynamic_entries=[(32, 0x300), (33, 8), (12, 0x1200)],
                has_interp=True,
            )
        )
        struct.pack_into("<Q", pie_raw, 0x300, 0x1300)
        pie = _BinaryView(
            [_Function(0x101000, "main"), _Function(0x101200, "init"), _Function(0x101300, "preinit")],
            bytes(pie_raw),
            0x101000,
        )
        pie_route = self._startup_route(pie)
        self.assertEqual(pie_route["target_kind"], "pie")
        self.assertEqual([entry["stage"] for entry in pie_route["entries"]], ["preinit_array", "init", "elf_entry", "main"])

        dynamic = [(12, 0x1200), (25, 0x320), (27, 8)]
        shared_raw = bytearray(_elf64(elf_type=3, entry=0, dynamic_entries=dynamic))
        struct.pack_into("<Q", shared_raw, 0x320, 0x1300)
        jni = _Function(0x1400, "JNI_OnLoad")
        shared = _BinaryView([_Function(0x1200, "init"), _Function(0x1300, "ctor"), jni], bytes(shared_raw), 0)
        shared_route = self._startup_route(shared)
        self.assertEqual(shared_route["target_kind"], "shared_library")
        self.assertEqual([entry["stage"] for entry in shared_route["entries"]], ["init", "init_array", "jni_on_load"])

        unknown_raw = bytearray(
            _elf64(elf_type=3, entry=0, dynamic_entries=[(12, 0x1200), (14, 0)], has_interp=True)
        )
        unknown = _BinaryView([_Function(0x1200, "init"), jni], bytes(unknown_raw), 0)
        unknown_route = self._startup_route(unknown)
        self.assertEqual(unknown_route["target_kind"], "unknown")
        self.assertEqual(unknown_route["entries"], [{"id": "0x1200", "stage": "init"}])

        non_target = _BinaryView(
            [_Function(0x1200, "init")],
            _elf64(elf_type=1, entry=0, dynamic_entries=[(12, 0x1200)]),
            0,
        )
        self.assertEqual(self._startup_route(non_target)["entries"], [])

    def test_bionic_main_requires_the_direct_crt_argument_pattern(self) -> None:
        raw = _elf64(elf_type=2, entry=0x1000, dynamic_entries=[])
        libc_init = _Function(0x1100, "__libc_init")
        main = _Function(0x1200, None)
        crt = _Function(
            0x1000,
            "_start_main",
            mlil=[
                _instruction(
                    "MLIL_CALL",
                    0x1010,
                    libc_init.start,
                    [SimpleNamespace(), SimpleNamespace(), SimpleNamespace(constant=main.start)],
                )
            ],
        )
        bv = _BinaryView([crt, libc_init, main], raw, crt.start)
        route = self._startup_route(bv)
        self.assertIn({"id": "0x1200", "stage": "main"}, route["entries"])

        crt.medium_level_il = _Il([_instruction("MLIL_CALL", 0x1010, libc_init.start, [SimpleNamespace()])])
        decoy = _Function(
            0x1300,
            "not_crt",
            mlil=[
                _instruction(
                    "MLIL_CALL",
                    0x1310,
                    libc_init.start,
                    [SimpleNamespace(), SimpleNamespace(), SimpleNamespace(constant=main.start)],
                )
            ],
        )
        bv.functions.append(decoy)
        route = self._startup_route(bv)
        self.assertNotIn({"id": "0x1200", "stage": "main"}, route["entries"])

    def test_hlil_and_pseudoc_only_prefix_mapped_source_lines(self) -> None:
        lines = [
            _Line("value = 1;", 0x88504, mapped=True),
            _Line("{", 0x88504, mapped=False),
            _Line("commented\n\nsecond;", 0x88508, mapped=True),
        ]
        function = _Function(0x88504, "f")
        function.get_comment_at = lambda address: "note" if address == 0x88504 else None
        function.get_type_tokens = lambda: [SimpleNamespace(tokens=[_Token("int f(void)")])]
        function.pseudo_c_if_available = SimpleNamespace(get_linear_lines=lambda root: lines)
        bv = _BinaryView([function], _elf64(elf_type=2, entry=function.start, dynamic_entries=[]), function.start)
        bv.linear_lines = lines

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "snapshot"
            run_export(bv, ExportConfig(output_dir=output_dir, export_pseudoc=True))
            rendered = (output_dir / "functions" / "f.hlil.txt").read_text(encoding="utf-8")
            pseudoc = (output_dir / "optional" / "pseudoc" / "f.pseudoc.c").read_text(encoding="utf-8")

        self.assertIn("0x88504", rendered)
        self.assertIn("note", rendered)
        self.assertIn("                  {", rendered)
        self.assertIn("                  // declaration: int f(void)", rendered)
        self.assertIn("\n                  \n", rendered)
        self.assertNotIn("0x0000000000088504", rendered)
        self.assertIn("0x88508", pseudoc)
        self.assertIn("                  {", pseudoc)

    def test_function_artifact_names_use_function_names_and_default_sub_names(self) -> None:
        named = _Function(0x101000, "main")
        unnamed = _Function(0x101200, None)
        bv = _BinaryView([named, unnamed], _elf64(elf_type=2, entry=named.start, dynamic_entries=[]), named.start)

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "snapshot"
            run_export(bv, ExportConfig(output_dir=output_dir))

            self.assertTrue((output_dir / "functions" / "main.hlil.txt").exists())
            self.assertTrue((output_dir / "functions" / "sub_101200.hlil.txt").exists())
            self.assertFalse((output_dir / "functions" / "0x101000.hlil.txt").exists())

    def test_background_task_progress_includes_name_or_id_and_clears_it_at_end(self) -> None:
        import binja_no_mcp.plugin as plugin

        bv = self._executable_view()
        bv.functions[1].name = None
        bv.functions[1].symbol = None
        cfg = ExportConfig(output_dir=Path(tempfile.mkdtemp()), reanalyze_before_export=True)

        class TaskSurrogate:
            def __init__(self, view: _BinaryView = bv, config: ExportConfig = cfg, function_keys: list[tuple[int, str | None]] | None = None) -> None:
                self._bv = view
                self._cfg = config
                self._function_keys = function_keys or [(function.start, "aarch64") for function in view.functions[:2]]
                self._function_labels: dict[tuple[int, str | None], str] = {}
                self.cancelled = False
                self.history: list[str] = []

            @property
            def progress(self) -> str:
                return self.history[-1] if self.history else ""

            @progress.setter
            def progress(self, value: str) -> None:
                self.history.append(value)

        task = TaskSurrogate()

        def start_reanalysis(function: _Function, time_limit_seconds: int) -> object:
            function.reanalyze()
            return SimpleNamespace()

        def completed_reanalysis(
            function: _Function,
            time_limit_seconds: int,
            is_cancelled: object,
            on_progress: object = None,
            is_skip_requested: object = None,
            reanalysis_requested_at: object = None,
            post_request_work_observed: bool = False,
            is_memory_ceiling_reached: object = None,
            on_memory_ceiling: object = None,
        ) -> object:
            if on_progress is not None:
                on_progress(1.0)
            return SimpleNamespace(completed=True, reason=None, elapsed_seconds=0.0)

        with (
            patch.object(plugin, "execute_on_main_thread_and_wait", lambda callback: callback()),
            patch.object(plugin, "execute_on_main_thread", lambda callback: callback()),
            patch.object(plugin.analysis_guard, "start_function_reanalysis", start_reanalysis),
            patch.object(plugin.analysis_guard, "wait_for_function_workflow", completed_reanalysis),
            patch.object(plugin.analysis_guard, "restore_function_analysis_settings"),
            patch.object(plugin, "_show_completion"),
        ):
            plugin._ExportTask.run(task)

        self.assertTrue(any("main" in progress for progress in task.history))
        self.assertTrue(any("0x101200" in progress for progress in task.history))
        self.assertNotIn("main", task.history[-1])
        self.assertNotIn("0x101200", task.history[-1])

        cancelled = TaskSurrogate()

        def cancel_after_first_export(
            session: object,
            view: object,
            function_key: object,
            is_cancelled: object = None,
        ) -> None:
            cancelled.cancelled = True

        with (
            patch.object(plugin, "execute_on_main_thread_and_wait", lambda callback: callback()),
            patch.object(plugin, "execute_on_main_thread", lambda callback: callback()),
            patch.object(plugin.analysis_guard, "start_function_reanalysis", start_reanalysis),
            patch.object(plugin.analysis_guard, "wait_for_function_workflow", completed_reanalysis),
            patch.object(plugin.analysis_guard, "restore_function_analysis_settings"),
            patch.object(plugin, "export_function", cancel_after_first_export),
            patch.object(plugin, "_show_completion"),
        ):
            plugin._ExportTask.run(cancelled)

        self.assertEqual(cancelled.history[-1], "Export cancelled")
        self.assertNotIn("main", cancelled.history[-1])
        cancelled_header = json.loads((cfg.output_dir / "meta" / "binary.json").read_text(encoding="utf-8"))
        self.assertEqual(cancelled_header["snapshot_status"], "cancelled")

        failed_view = self._executable_view(needs_update=True)
        failed = TaskSurrogate(
            failed_view,
            ExportConfig(output_dir=Path(tempfile.mkdtemp()), reanalyze_before_export=False),
            [(function.start, "aarch64") for function in failed_view.functions[:2]],
        )
        with (
            patch.object(plugin, "execute_on_main_thread", lambda callback: callback()),
            patch.object(plugin, "_show_completion"),
        ):
            plugin._ExportTask.run(failed)

        self.assertEqual(failed.history[-1], "Export partial")
        self.assertNotIn("main", failed.history[-1])

        auto_symbol = _Function(0x101500, "sub_101500")
        auto_symbol.symbol.auto = True
        auto_view = _BinaryView([auto_symbol], b"", 0)
        auto_task = TaskSurrogate(
            auto_view,
            ExportConfig(output_dir=Path(tempfile.mkdtemp()), reanalyze_before_export=False),
            [(auto_symbol.start, "aarch64")],
        )
        with (
            patch.object(plugin, "execute_on_main_thread", lambda callback: callback()),
            patch.object(plugin, "_show_completion"),
        ):
            plugin._ExportTask.run(auto_task)
        self.assertTrue(any("0x101500" in progress for progress in auto_task.history))

    def test_reanalysis_waits_for_function_workflow_and_restores_budget(self) -> None:
        import binja_no_mcp.plugin as plugin

        bv = self._executable_view(needs_update=True)
        function = bv.functions[0]
        states = iter(("Active", "Idle"))

        class WorkflowMachine:
            def __init__(self) -> None:
                self.status_calls = 0

            def status(self) -> dict[str, object]:
                self.status_calls += 1
                state = next(states, "Idle")
                if state == "Idle":
                    function.needs_update = False
                return {"machineState": {"state": state, "activity": "extension.DispatchThis.Custom"}}

        machine = WorkflowMachine()
        function.workflow = SimpleNamespace(machine=machine)
        wait_calls: list[None] = []
        bv.update_analysis_and_wait = lambda: wait_calls.append(None)

        class SettingsSurrogate:
            def __init__(self) -> None:
                self.set_calls: list[tuple[str, int, object, object]] = []
                self.reset_calls: list[tuple[str, object, object]] = []
                self.restore_calls: list[tuple[str, object, object]] = []

            def contains(self, key: str) -> bool:
                return key == "analysis.limits.maxFunctionAnalysisTime"

            def serialize_settings(self, resource: object, scope: object) -> str:
                self.restore_calls.append(("saved", resource, scope))
                return "{}"

            def set_integer(self, key: str, value: int, resource: object, scope: object) -> bool:
                self.set_calls.append((key, value, resource, scope))
                return True

            def reset(self, key: str, resource: object, scope: object) -> bool:
                self.reset_calls.append((key, resource, scope))
                return True

            def deserialize_settings(self, value: str, resource: object, scope: object) -> bool:
                self.restore_calls.append((value, resource, scope))
                return True

        settings = SettingsSurrogate()
        cfg = ExportConfig(output_dir=Path(tempfile.mkdtemp()), reanalyze_before_export=True)

        class TaskSurrogate:
            def __init__(self) -> None:
                self._bv = bv
                self._cfg = cfg
                self._function_keys = [(function.start, "aarch64")]
                self._function_labels: dict[tuple[int, str | None], str] = {}
                self.cancelled = False
                self.history: list[str] = []

            @property
            def progress(self) -> str:
                return self.history[-1] if self.history else ""

            @progress.setter
            def progress(self, value: str) -> None:
                self.history.append(value)

        task = TaskSurrogate()
        settings_scope = SimpleNamespace(SettingsResourceScope="resource")
        with (
            patch.object(plugin.analysis_guard, "Settings", return_value=settings),
            patch.object(plugin.analysis_guard, "SettingsScope", settings_scope),
            patch.object(plugin.analysis_guard, "sleep", lambda _: None),
            patch.object(plugin, "execute_on_main_thread_and_wait", lambda callback: callback()),
            patch.object(plugin, "execute_on_main_thread", lambda callback: callback()),
            patch.object(plugin, "_show_completion"),
            patch.object(plugin, "_show_failure"),
        ):
            plugin._ExportTask.run(task)

        self.assertTrue(function.reanalyzed)
        self.assertEqual(wait_calls, [])
        self.assertGreaterEqual(machine.status_calls, 2)
        self.assertEqual(settings.set_calls, [("analysis.limits.maxFunctionAnalysisTime", 900000, function, "resource")])
        self.assertEqual(settings.reset_calls, [("analysis.limits.maxFunctionAnalysisTime", function, "resource")])
        self.assertEqual(settings.restore_calls, [("saved", function, "resource"), ("{}", function, "resource")])
        header = json.loads((cfg.output_dir / "meta" / "binary.json").read_text(encoding="utf-8"))
        self.assertEqual(header["snapshot_status"], "complete")

    def test_deferred_reanalysis_is_partial_without_stale_artifacts(self) -> None:
        import binja_no_mcp.plugin as plugin

        bv = self._executable_view(needs_update=True)
        function = bv.functions[0]
        function.analysis_skip_reason = plugin.analysis_guard.AnalysisSkipReason.ExceedFunctionAnalysisTimeSkipReason
        cfg = ExportConfig(output_dir=Path(tempfile.mkdtemp()), reanalyze_before_export=True)
        task = SimpleNamespace(
            _bv=bv,
            _cfg=cfg,
            _function_keys=[(function.start, "aarch64")],
            _function_labels={},
            cancelled=False,
            progress="",
        )

        def start_reanalysis(deferred: _Function, time_limit_seconds: int) -> object:
            deferred.reanalyze()
            deferred.analysis_skipped = True
            return SimpleNamespace()

        with (
            patch.object(plugin, "execute_on_main_thread_and_wait", lambda callback: callback()),
            patch.object(plugin, "execute_on_main_thread", lambda callback: callback()),
            patch.object(plugin.analysis_guard, "start_function_reanalysis", start_reanalysis),
            patch.object(plugin.analysis_guard, "restore_function_analysis_settings"),
            patch.object(plugin, "_show_completion"),
            patch.object(plugin, "_show_failure"),
        ):
            plugin._ExportTask.run(task)

        header = json.loads((cfg.output_dir / "meta" / "binary.json").read_text(encoding="utf-8"))
        failures = [
            json.loads(line)
            for line in (cfg.output_dir / "meta" / "failures.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        index = _index(cfg.output_dir)
        self.assertTrue(function.reanalyzed)
        self.assertEqual(header["snapshot_status"], "partial")
        self.assertEqual(index[0]["export_status"], "failed")
        self.assertFalse((cfg.output_dir / "functions" / "main.hlil.txt").exists())
        self.assertIn("analysis-deferred", [failure.get("reason") for failure in failures])

    def test_skip_waits_for_a_terminal_workflow_state_before_continuing(self) -> None:
        from binja_no_mcp import analysis_guard

        function = _Function(0x101000, "main", needs_update=True)
        states = iter(("Active", "Idle"))

        class WorkflowMachine:
            def __init__(self) -> None:
                self.status_calls = 0

            def status(self) -> dict[str, object]:
                self.status_calls += 1
                return {"machineState": {"state": next(states, "Idle")}}

        machine = WorkflowMachine()
        function.workflow = SimpleNamespace(machine=machine)

        with patch.object(analysis_guard, "sleep", lambda _: None):
            result = analysis_guard.wait_for_function_workflow(
                function,
                900,
                lambda: False,
                is_skip_requested=lambda: True,
            )

        self.assertFalse(result.completed)
        self.assertEqual(result.reason, "skipped")
        self.assertEqual(machine.status_calls, 2)

    def test_reanalysis_completes_after_observing_an_active_workflow(self) -> None:
        from binja_no_mcp import analysis_guard

        function = _Function(0x101000, "main")
        states = iter(("Active", "Idle"))

        class WorkflowMachine:
            def __init__(self) -> None:
                self.status_calls = 0

            def status(self) -> dict[str, object]:
                self.status_calls += 1
                state = next(states, "Idle")
                if state == "Idle":
                    function.needs_update = False
                return {"machineState": {"state": state}}

        function.workflow = SimpleNamespace(machine=WorkflowMachine())
        clock = [0.0]

        def advance_clock(_: float) -> None:
            clock[0] += analysis_guard.WORKFLOW_POLL_INTERVAL_SECONDS

        with (
            patch.object(analysis_guard, "monotonic", lambda: clock[0]),
            patch.object(analysis_guard, "sleep", advance_clock),
        ):
            result = analysis_guard.wait_for_function_workflow(function, 900, lambda: False)

        self.assertTrue(result.completed)
        self.assertEqual(function.workflow.machine.status_calls, 2)

    def test_reanalysis_without_post_request_work_is_unconfirmed(self) -> None:
        from binja_no_mcp import analysis_guard

        function = _Function(0x101000, "main")

        class WorkflowMachine:
            def __init__(self) -> None:
                self.status_calls = 0

            def status(self) -> dict[str, object]:
                self.status_calls += 1
                return {"machineState": {"state": "Idle"}}

        function.workflow = SimpleNamespace(machine=WorkflowMachine())
        clock = [0.0]

        def advance_clock(_: float) -> None:
            clock[0] += analysis_guard.WORKFLOW_POLL_INTERVAL_SECONDS

        with patch.object(analysis_guard, "monotonic", lambda: clock[0]):
            result = analysis_guard.wait_for_function_workflow(function, 0.2, lambda: False)

        self.assertFalse(result.completed)
        self.assertEqual(result.reason, "analysis-unconfirmed")
        self.assertEqual(function.workflow.machine.status_calls, 1)

    def test_post_request_pending_signal_allows_fast_workflow_completion(self) -> None:
        from binja_no_mcp import analysis_guard

        function = _Function(0x101000, "main")
        function.reanalyze = lambda: setattr(function, "needs_update", True)

        class SettingsSurrogate:
            def serialize_settings(self, resource: object, scope: object) -> str:
                return "original"

            def set_integer(self, key: str, value: int, resource: object, scope: object) -> bool:
                return True

            def reset(self, key: str, resource: object, scope: object) -> bool:
                return True

            def deserialize_settings(self, value: str, resource: object, scope: object) -> bool:
                return True

        settings_scope = SimpleNamespace(SettingsResourceScope="resource")
        with (
            patch.object(analysis_guard, "Settings", return_value=SettingsSurrogate()),
            patch.object(analysis_guard, "SettingsScope", settings_scope),
        ):
            snapshot = analysis_guard.start_function_reanalysis(function, 900)

        self.assertTrue(snapshot.post_request_work_observed)
        function.needs_update = False
        function.workflow = SimpleNamespace(
            machine=SimpleNamespace(status=lambda: {"machineState": {"state": "Idle"}})
        )
        result = analysis_guard.wait_for_function_workflow(
            function,
            900,
            lambda: False,
            post_request_work_observed=snapshot.post_request_work_observed,
        )

        self.assertTrue(result.completed)

    def test_reanalysis_memory_ceiling_requests_one_halt_and_waits_for_terminal_state(self) -> None:
        from binja_no_mcp import analysis_guard

        function = _Function(0x101000, "main", needs_update=True)
        states = iter(("Active", "Active", "Idle"))

        class WorkflowMachine:
            def __init__(self) -> None:
                self.status_calls = 0

            def status(self) -> dict[str, object]:
                self.status_calls += 1
                state = next(states, "Idle")
                if state == "Idle":
                    function.needs_update = False
                return {"machineState": {"state": state}}

        function.workflow = SimpleNamespace(machine=WorkflowMachine())
        halt_requests: list[None] = []

        with patch.object(analysis_guard, "sleep", lambda _: None):
            result = analysis_guard.wait_for_function_workflow(
                function,
                900,
                lambda: False,
                is_memory_ceiling_reached=lambda: True,
                on_memory_ceiling=lambda: halt_requests.append(None),
            )

        self.assertFalse(result.completed)
        self.assertEqual(result.reason, "memory-ceiling")
        self.assertEqual(halt_requests, [None])
        self.assertEqual(function.workflow.machine.status_calls, 3)

    def test_reanalysis_start_failure_restores_function_settings(self) -> None:
        from binja_no_mcp import analysis_guard

        function = _Function(0x101000, "main")
        function.reanalyze = lambda: (_ for _ in ()).throw(RuntimeError("reanalyze failed"))

        class SettingsSurrogate:
            def __init__(self) -> None:
                self.calls: list[tuple[object, ...]] = []

            def serialize_settings(self, resource: object, scope: object) -> str:
                self.calls.append(("serialize", resource, scope))
                return "original"

            def set_integer(self, key: str, value: int, resource: object, scope: object) -> bool:
                self.calls.append(("set", key, value, resource, scope))
                return True

            def reset(self, key: str, resource: object, scope: object) -> bool:
                self.calls.append(("reset", key, resource, scope))
                return True

            def deserialize_settings(self, value: str, resource: object, scope: object) -> bool:
                self.calls.append(("deserialize", value, resource, scope))
                return True

        settings = SettingsSurrogate()
        settings_scope = SimpleNamespace(SettingsResourceScope="resource")
        with (
            patch.object(analysis_guard, "Settings", return_value=settings),
            patch.object(analysis_guard, "SettingsScope", settings_scope),
            self.assertRaisesRegex(RuntimeError, "reanalyze failed"),
        ):
            analysis_guard.start_function_reanalysis(function, 900)

        self.assertEqual(
            settings.calls,
            [
                ("serialize", function, "resource"),
                ("set", "analysis.limits.maxFunctionAnalysisTime", 900000, function, "resource"),
                ("reset", "analysis.limits.maxFunctionAnalysisTime", function, "resource"),
                ("deserialize", "original", function, "resource"),
            ],
        )

    def test_export_timeout_stops_one_function_and_continues_next(self) -> None:
        import binja_no_mcp.export_runner as export_runner

        bv = self._executable_view()
        first, second = bv.functions[:2]
        clock = [0.0]
        pseudoc_calls: list[int] = []

        def render_hlil(hlil: object, declaration: str | None) -> str:
            if hlil.source_function.start == first.start:
                clock[0] += 901.0
            return "return;\n"

        def render_pseudoc(hlil: object, declaration: str | None) -> str:
            pseudoc_calls.append(hlil.source_function.start)
            return "void f(void) {}\n"

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "snapshot"
            with (
                patch.object(export_runner, "monotonic", lambda: clock[0], create=True),
                patch.object(export_runner, "render_hlil", render_hlil),
                patch.object(export_runner, "render_pseudoc", render_pseudoc),
            ):
                summary = run_export(
                    bv,
                    ExportConfig(output_dir=output_dir, export_pseudoc=True),
                    function_keys=[(first.start, "aarch64"), (second.start, "aarch64")],
                )

            header = json.loads((output_dir / "meta" / "binary.json").read_text(encoding="utf-8"))
            failures = [
                json.loads(line)
                for line in (output_dir / "meta" / "failures.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            index = _index(output_dir)

        self.assertEqual(summary.status, "partial")
        self.assertEqual(header["snapshot_status"], "partial")
        self.assertEqual(index[0]["export_status"], "partial")
        self.assertEqual(index[1]["export_status"], "exported")
        self.assertNotIn(first.start, pseudoc_calls)
        self.assertIn(second.start, pseudoc_calls)
        self.assertIn("export-timeout", [failure.get("reason") for failure in failures])

    def test_export_timeout_after_meta_write_is_not_marked_complete(self) -> None:
        import binja_no_mcp.export_runner as export_runner

        bv = self._executable_view()
        function = bv.functions[0]
        clock = [0.0]
        original_write_json = export_runner.write_json

        def write_json(path: Path, data: object) -> None:
            original_write_json(path, data)
            if path.name.endswith(".meta.json"):
                clock[0] += 901.0

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "snapshot"
            with (
                patch.object(export_runner, "monotonic", lambda: clock[0]),
                patch.object(export_runner, "write_json", write_json),
            ):
                summary = run_export(
                    bv,
                    ExportConfig(output_dir=output_dir),
                    function_keys=[(function.start, "aarch64")],
                )

            header = json.loads((output_dir / "meta" / "binary.json").read_text(encoding="utf-8"))
            index = _index(output_dir)
            failures = [
                json.loads(line)
                for line in (output_dir / "meta" / "failures.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(summary.status, "partial")
        self.assertEqual(header["snapshot_status"], "partial")
        self.assertEqual(index[0]["export_status"], "partial")
        self.assertIn("export-timeout", [failure.get("reason") for failure in failures])

    def test_memory_ceiling_skips_one_function_and_continues_without_aborting_analysis(self) -> None:
        import binja_no_mcp.export_runner as export_runner

        bv = self._executable_view()
        first, second = bv.functions[:2]
        bv.abort_analysis_calls = 0

        class MemoryWindow:
            def to_dict(self) -> dict[str, int]:
                return {
                    "baseline_private_usage": 10,
                    "peak_private_usage": 24 * 1024**3,
                    "end_private_usage": 24 * 1024**3,
                    "private_usage_delta": 24 * 1024**3 - 10,
                    "baseline_working_set": 5,
                    "peak_working_set": 7,
                    "end_working_set": 7,
                }

        class MemoryMonitor:
            def __init__(self) -> None:
                self.exceeded = False
                self.started = False
                self.stopped = False
                self.begin_window_calls = 0

            def start(self) -> None:
                self.started = True

            def begin_window(self) -> None:
                self.begin_window_calls += 1
                self.exceeded = False

            def end_window(self) -> MemoryWindow:
                return MemoryWindow()

            def stop(self) -> None:
                self.stopped = True

        monitor = MemoryMonitor()

        def render_hlil(hlil: object, declaration: str | None) -> str:
            if hlil.source_function.start == first.start:
                monitor.exceeded = True
            return "return;\n"

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "snapshot"
            with (
                patch.object(export_runner, "ProcessMemoryMonitor", return_value=monitor, create=True),
                patch.object(export_runner, "render_hlil", render_hlil),
            ):
                summary = run_export(
                    bv,
                    ExportConfig(output_dir=output_dir, private_memory_limit_gib=24),
                    function_keys=[(first.start, "aarch64"), (second.start, "aarch64")],
                )

            header = json.loads((output_dir / "meta" / "binary.json").read_text(encoding="utf-8"))
            failures = [
                json.loads(line)
                for line in (output_dir / "meta" / "failures.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            index = _index(output_dir)

        memory_failure = next(failure for failure in failures if failure.get("reason") == "memory-ceiling")
        self.assertEqual(summary.status, "partial")
        self.assertEqual(header["snapshot_status"], "partial")
        self.assertEqual(index[0]["export_status"], "partial")
        self.assertEqual(index[1]["export_status"], "exported")
        self.assertEqual(index[0]["memory_window"]["peak_private_usage"], 24 * 1024**3)
        self.assertGreaterEqual(monitor.begin_window_calls, 2)
        self.assertTrue(monitor.started)
        self.assertTrue(monitor.stopped)
        self.assertEqual(bv.abort_analysis_calls, 0)
        self.assertEqual(memory_failure["memory_window"]["peak_private_usage"], 24 * 1024**3)

    def test_memory_ceiling_at_a_new_function_boundary_does_not_block_export(self) -> None:
        import binja_no_mcp.export_runner as export_runner

        bv = self._executable_view()
        rendered: list[int] = []

        class MemoryMonitor:
            def __init__(self) -> None:
                self.exceeded = True

            def start(self) -> None:
                return None

            def begin_window(self) -> None:
                self.exceeded = False

            def end_window(self) -> object:
                return SimpleNamespace(to_dict=lambda: {})

            def stop(self) -> None:
                return None

        def render_hlil(hlil: object, declaration: str | None) -> str:
            rendered.append(hlil.source_function.start)
            return "return;\n"

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "snapshot"
            with (
                patch.object(export_runner, "ProcessMemoryMonitor", return_value=MemoryMonitor()),
                patch.object(export_runner, "render_hlil", render_hlil),
            ):
                summary = run_export(
                    bv,
                    ExportConfig(output_dir=output_dir),
                    function_keys=[(function.start, "aarch64") for function in bv.functions[:2]],
                )
            failures = [
                json.loads(line)
                for line in (output_dir / "meta" / "failures.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            index = _index(output_dir)

        self.assertEqual(summary.status, "complete")
        self.assertEqual(rendered, [function.start for function in bv.functions[:2]])
        self.assertTrue(all(record["export_status"] == "exported" for record in index))
        self.assertEqual(failures, [])

    def test_memory_monitor_records_peak_window_without_binary_view_access(self) -> None:
        from binja_no_mcp import resource_monitor

        monitor = resource_monitor.ProcessMemoryMonitor(private_usage_limit_bytes=100)
        samples = [
            resource_monitor.ProcessMemorySample(private_usage=10, working_set=5),
            resource_monitor.ProcessMemorySample(private_usage=120, working_set=8),
            resource_monitor.ProcessMemorySample(private_usage=110, working_set=7),
        ]

        with patch.object(resource_monitor, "_process_memory_sample", side_effect=samples):
            monitor.begin_window()
            monitor._capture()
            window = monitor.end_window()

        self.assertTrue(monitor.exceeded)
        self.assertEqual(window.baseline_private_usage, 10)
        self.assertEqual(window.peak_private_usage, 120)
        self.assertEqual(window.end_private_usage, 110)
        self.assertEqual(window.private_usage_delta, 110)

    def test_memory_monitor_ignores_an_already_high_new_window_baseline(self) -> None:
        from binja_no_mcp import resource_monitor

        monitor = resource_monitor.ProcessMemoryMonitor(private_usage_limit_bytes=100)
        samples = [
            resource_monitor.ProcessMemorySample(private_usage=120, working_set=8),
            resource_monitor.ProcessMemorySample(private_usage=130, working_set=9),
            resource_monitor.ProcessMemorySample(private_usage=125, working_set=8),
        ]

        with patch.object(resource_monitor, "_process_memory_sample", side_effect=samples):
            monitor.begin_window()
            monitor._capture()
            monitor.end_window()

        self.assertFalse(monitor.exceeded)

    def test_each_exported_function_index_records_its_memory_window(self) -> None:
        import binja_no_mcp.export_runner as export_runner

        bv = self._executable_view()

        class MemoryWindow:
            def __init__(self, baseline: int) -> None:
                self._baseline = baseline

            def to_dict(self) -> dict[str, int]:
                return {
                    "baseline_private_usage": self._baseline,
                    "peak_private_usage": self._baseline + 3,
                    "end_private_usage": self._baseline + 2,
                    "private_usage_delta": 3,
                    "baseline_working_set": self._baseline,
                    "peak_working_set": self._baseline + 1,
                    "end_working_set": self._baseline + 1,
                    "working_set_delta": 1,
                }

        class MemoryMonitor:
            def __init__(self) -> None:
                self.exceeded = False
                self.begin_window_calls = 0
                self.end_window_calls = 0

            def start(self) -> None:
                return None

            def begin_window(self) -> None:
                self.begin_window_calls += 1

            def end_window(self) -> MemoryWindow:
                self.end_window_calls += 1
                return MemoryWindow(self.end_window_calls * 10)

            def stop(self) -> None:
                return None

        monitor = MemoryMonitor()
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "snapshot"
            with patch.object(export_runner, "ProcessMemoryMonitor", return_value=monitor):
                summary = run_export(
                    bv,
                    ExportConfig(output_dir=output_dir),
                    function_keys=[(function.start, "aarch64") for function in bv.functions[:2]],
                )
            index = _index(output_dir)

        self.assertEqual(summary.status, "complete")
        self.assertEqual(monitor.begin_window_calls, 3)
        self.assertEqual(monitor.end_window_calls, 3)
        self.assertEqual(index[0]["memory_window"]["baseline_private_usage"], 10)
        self.assertEqual(index[1]["memory_window"]["baseline_private_usage"], 20)

    def test_incremental_export_reuses_successful_functions(self) -> None:
        import binja_no_mcp.export_runner as export_runner

        bv = self._executable_view(needs_update=True)
        function_keys = [(function.start, "aarch64") for function in bv.functions]
        first = bv.functions[0]
        rendered: list[int] = []

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "snapshot"
            first_summary = run_export(
                bv,
                ExportConfig(output_dir=output_dir, reanalyze_before_export=False),
                function_keys=function_keys,
            )
            self.assertEqual(first_summary.status, "partial")

            first.needs_update = False

            def render_hlil(hlil: object, declaration: str | None) -> str:
                rendered.append(hlil.source_function.start)
                return "return;\n"

            with patch.object(export_runner, "render_hlil", render_hlil):
                summary = run_export(
                    bv,
                    ExportConfig(output_dir=output_dir, reanalyze_before_export=False, incremental=True),
                    function_keys=function_keys,
                )

            header = json.loads((output_dir / "meta" / "binary.json").read_text(encoding="utf-8"))
            index = _index(output_dir)

        self.assertEqual(summary.status, "complete")
        self.assertEqual(rendered, [first.start])
        self.assertEqual(header["exported_function_count"], len(function_keys))
        self.assertTrue(all(record["export_status"] == "exported" for record in index))

    def test_incremental_export_accepts_bndb_for_the_same_original_binary(self) -> None:
        # Given: a partial snapshot created from an original binary file.
        bv = self._executable_view(needs_update=True)
        function_keys = [(function.start, "aarch64") for function in bv.functions]

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "snapshot"
            run_export(
                bv,
                ExportConfig(output_dir=output_dir, reanalyze_before_export=False),
                function_keys=function_keys,
            )
            bv.functions[0].needs_update = False
            bv.file.filename = "fixture.bndb"
            bv.file.original_filename = "fixture.so"

            # When: the same analysis is resumed from its Binary Ninja database.
            summary = run_export(
                bv,
                ExportConfig(output_dir=output_dir, reanalyze_before_export=False, incremental=True),
                function_keys=function_keys,
            )

        # Then: the snapshot is accepted and completed.
        self.assertEqual(summary.status, "complete")

    def test_memory_ceiling_during_reanalysis_skips_the_function_and_continues(self) -> None:
        import binja_no_mcp.export_runner as export_runner
        import binja_no_mcp.plugin as plugin

        bv = self._executable_view(needs_update=True)
        function, next_function = bv.functions[:2]
        cfg = ExportConfig(output_dir=Path(tempfile.mkdtemp()), reanalyze_before_export=True)

        class MemoryWindow:
            def to_dict(self) -> dict[str, int]:
                return {
                    "baseline_private_usage": 11,
                    "peak_private_usage": 24 * 1024**3,
                    "end_private_usage": 24 * 1024**3,
                    "private_usage_delta": 24 * 1024**3 - 11,
                    "baseline_working_set": 5,
                    "peak_working_set": 7,
                    "end_working_set": 7,
                    "working_set_delta": 2,
                }

        class MemoryMonitor:
            def __init__(self) -> None:
                self.exceeded = False
                self.begin_window_calls = 0
                self.end_window_calls = 0
                self.stopped = False

            def start(self) -> None:
                return None

            def begin_window(self) -> None:
                self.begin_window_calls += 1
                self.exceeded = False

            def end_window(self) -> MemoryWindow:
                self.end_window_calls += 1
                return MemoryWindow()

            def stop(self) -> None:
                self.stopped = True

        monitor = MemoryMonitor()
        task = SimpleNamespace(
            _bv=bv,
            _cfg=cfg,
            _function_keys=[(function.start, "aarch64"), (next_function.start, "aarch64")],
            _function_labels={},
            cancelled=False,
            progress="",
        )

        def start_reanalysis(target: _Function, time_limit_seconds: int) -> object:
            target.reanalyze()
            return SimpleNamespace()

        def wait_for_analysis(
            target: _Function,
            time_limit_seconds: int,
            is_cancelled: object,
            on_progress: object = None,
            is_skip_requested: object = None,
            reanalysis_requested_at: object = None,
            post_request_work_observed: bool = False,
            is_memory_ceiling_reached: object = None,
            on_memory_ceiling: object = None,
        ) -> object:
            if target is function:
                monitor.exceeded = True
            return SimpleNamespace(completed=True, reason=None, elapsed_seconds=4.0)

        with (
            patch.object(export_runner, "ProcessMemoryMonitor", return_value=monitor),
            patch.object(plugin, "execute_on_main_thread_and_wait", lambda callback: callback()),
            patch.object(plugin, "execute_on_main_thread", lambda callback: callback()),
            patch.object(plugin.analysis_guard, "start_function_reanalysis", start_reanalysis),
            patch.object(plugin.analysis_guard, "wait_for_function_workflow", wait_for_analysis),
            patch.object(plugin.analysis_guard, "restore_function_analysis_settings"),
            patch.object(plugin, "_show_completion"),
        ):
            plugin._ExportTask.run(task)

        failures = [
            json.loads(line)
            for line in (cfg.output_dir / "meta" / "failures.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        index = _index(cfg.output_dir)
        header = json.loads((cfg.output_dir / "meta" / "binary.json").read_text(encoding="utf-8"))

        self.assertEqual(header["snapshot_status"], "partial")
        self.assertEqual(index[0]["export_status"], "failed")
        self.assertEqual(index[1]["export_status"], "exported")
        self.assertFalse((cfg.output_dir / "functions" / "main.hlil.txt").exists())
        self.assertTrue((cfg.output_dir / "functions" / "target.hlil.txt").exists())
        self.assertGreaterEqual(monitor.begin_window_calls, 2)
        self.assertGreaterEqual(monitor.end_window_calls, 2)
        self.assertTrue(monitor.stopped)
        self.assertIn("memory-ceiling", [failure.get("reason") for failure in failures])

    def test_memory_ceiling_during_global_export_stops_remaining_collectors(self) -> None:
        import binja_no_mcp.export_runner as export_runner

        bv = self._executable_view()

        class MemoryWindow:
            def to_dict(self) -> dict[str, int]:
                return {
                    "baseline_private_usage": 1,
                    "peak_private_usage": 24 * 1024**3,
                    "end_private_usage": 24 * 1024**3,
                    "private_usage_delta": 24 * 1024**3 - 1,
                    "baseline_working_set": 1,
                    "peak_working_set": 2,
                    "end_working_set": 2,
                    "working_set_delta": 1,
                }

        class MemoryMonitor:
            def __init__(self) -> None:
                self.exceeded = False

            def start(self) -> None:
                return None

            def begin_window(self) -> None:
                return None

            def end_window(self) -> MemoryWindow:
                return MemoryWindow()

            def stop(self) -> None:
                return None

        monitor = MemoryMonitor()
        segments_called: list[None] = []

        def collect_sections(view: object) -> list[object]:
            monitor.exceeded = True
            return []

        def collect_segments(view: object) -> list[object]:
            segments_called.append(None)
            return []

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "snapshot"
            with (
                patch.object(export_runner, "ProcessMemoryMonitor", return_value=monitor),
                patch.object(export_runner, "collect_section_records", collect_sections),
                patch.object(export_runner, "collect_segment_records", collect_segments),
            ):
                summary = run_export(
                    bv,
                    ExportConfig(output_dir=output_dir),
                    function_keys=[(bv.functions[0].start, "aarch64")],
                )

            failures = [
                json.loads(line)
                for line in (output_dir / "meta" / "failures.jsonl").read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(summary.status, "partial")
        self.assertEqual(segments_called, [])
        self.assertIn("memory-ceiling", [failure.get("reason") for failure in failures])

    def test_skip_current_function_halts_its_workflow_and_continues(self) -> None:
        import binja_no_mcp.plugin as plugin

        bv = self._executable_view()
        first, second = bv.functions[:2]

        class WorkflowMachine:
            def __init__(self) -> None:
                self.halt_calls = 0

            def halt(self) -> None:
                self.halt_calls += 1

        first_machine = WorkflowMachine()
        first.workflow = SimpleNamespace(machine=first_machine)
        second.workflow = SimpleNamespace(machine=WorkflowMachine())
        cfg = ExportConfig(output_dir=Path(tempfile.mkdtemp()), reanalyze_before_export=True)

        class TaskSurrogate:
            def __init__(self) -> None:
                self._bv = bv
                self._cfg = cfg
                self._function_keys = [(first.start, "aarch64"), (second.start, "aarch64")]
                self._function_labels: dict[tuple[int, str | None], str] = {}
                self.cancelled = False
                self.history: list[str] = []

            @property
            def progress(self) -> str:
                return self.history[-1] if self.history else ""

            @progress.setter
            def progress(self, value: str) -> None:
                self.history.append(value)

        task = TaskSurrogate()

        def start_reanalysis(function: _Function, time_limit_seconds: int) -> object:
            function.reanalyze()
            return SimpleNamespace()

        def wait_for_analysis(
            function: _Function,
            time_limit_seconds: int,
            is_cancelled: object,
            on_progress: object = None,
            is_skip_requested: object = None,
            reanalysis_requested_at: object = None,
            post_request_work_observed: bool = False,
            is_memory_ceiling_reached: object = None,
            on_memory_ceiling: object = None,
        ) -> object:
            if on_progress is not None:
                on_progress(3.0)
            if function is first:
                plugin._skip_current_function(bv)
                return SimpleNamespace(completed=False, reason="skipped", elapsed_seconds=3.0)
            return SimpleNamespace(completed=True, reason=None, elapsed_seconds=3.0)

        with (
            patch.object(plugin, "execute_on_main_thread_and_wait", lambda callback: callback()),
            patch.object(plugin, "execute_on_main_thread", lambda callback: callback()),
            patch.object(plugin.analysis_guard, "start_function_reanalysis", start_reanalysis),
            patch.object(plugin.analysis_guard, "wait_for_function_workflow", wait_for_analysis),
            patch.object(plugin.analysis_guard, "restore_function_analysis_settings"),
            patch.object(plugin, "_show_completion"),
        ):
            plugin._register_active_task(bv, task)
            plugin._ExportTask.run(task)

        failures = [
            json.loads(line)
            for line in (cfg.output_dir / "meta" / "failures.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        index = _index(cfg.output_dir)
        header = json.loads((cfg.output_dir / "meta" / "binary.json").read_text(encoding="utf-8"))

        self.assertEqual(first_machine.halt_calls, 1)
        self.assertEqual(index[0]["export_status"], "failed")
        self.assertEqual(index[1]["export_status"], "exported")
        self.assertIn("skipped", [failure.get("reason") for failure in failures])
        self.assertEqual(header["snapshot_status"], "partial")
        self.assertTrue(any("3s" in progress and "900s" in progress and "24 GiB" in progress for progress in task.history))
        self.assertIsNone(plugin._active_task_for(bv))

    def test_native_cancel_stops_at_the_next_artifact_boundary(self) -> None:
        import binja_no_mcp.export_runner as export_runner
        import binja_no_mcp.plugin as plugin

        bv = self._executable_view()
        first, second = bv.functions[:2]
        cfg = ExportConfig(output_dir=Path(tempfile.mkdtemp()), reanalyze_before_export=False, export_pseudoc=True)
        pseudoc_calls: list[int] = []

        class TaskSurrogate:
            def __init__(self) -> None:
                self._bv = bv
                self._cfg = cfg
                self._function_keys = [(first.start, "aarch64"), (second.start, "aarch64")]
                self._function_labels: dict[tuple[int, str | None], str] = {}
                self.cancelled = False
                self.progress = ""

        task = TaskSurrogate()

        def render_hlil(hlil: object, declaration: str | None) -> str:
            task.cancelled = True
            return "return;\n"

        def render_pseudoc(hlil: object, declaration: str | None) -> str:
            pseudoc_calls.append(hlil.source_function.start)
            return "void f(void) {}\n"

        with (
            patch.object(export_runner, "render_hlil", render_hlil),
            patch.object(export_runner, "render_pseudoc", render_pseudoc),
            patch.object(plugin, "execute_on_main_thread", lambda callback: callback()),
            patch.object(plugin, "_show_completion"),
        ):
            plugin._ExportTask.run(task)

        header = json.loads((cfg.output_dir / "meta" / "binary.json").read_text(encoding="utf-8"))
        index = _index(cfg.output_dir)
        failures = [
            json.loads(line)
            for line in (cfg.output_dir / "meta" / "failures.jsonl").read_text(encoding="utf-8").splitlines()
        ]

        self.assertEqual(header["snapshot_status"], "cancelled")
        self.assertEqual(index[0]["export_status"], "partial")
        self.assertEqual(index[1]["export_status"], "not_exported")
        self.assertEqual(pseudoc_calls, [])
        self.assertIn("cancelled", [failure.get("reason") for failure in failures])

    def test_export_task_enables_native_background_task_cancellation(self) -> None:
        import binja_no_mcp.plugin as plugin

        bv = self._executable_view()
        cfg = ExportConfig(output_dir=Path(tempfile.mkdtemp()))
        calls: list[tuple[str, bool]] = []

        def initialize_task(task: object, title: str, can_cancel: bool) -> None:
            calls.append((title, can_cancel))

        with (
            patch.object(plugin.BackgroundTaskThread, "__init__", initialize_task),
            patch.object(plugin.BackgroundTaskThread, "__del__", lambda task: None),
        ):
            task = plugin._ExportTask(bv, cfg, [(bv.functions[0].start, "aarch64")])
            del task

        self.assertEqual(calls, [("Preparing export for AI", True)])

    def test_export_form_writes_editable_time_and_memory_limits_to_config(self) -> None:
        import binja_no_mcp.plugin as plugin

        bv = self._executable_view()
        output_dir = Path(tempfile.mkdtemp()) / "snapshot"
        integer_fields: list[tuple[str, int]] = []

        def integer_field(label: str, default: int) -> object:
            integer_fields.append((label, default))
            value = 901 if "time limit" in label else 25
            return SimpleNamespace(result=value)

        checkbox_fields: list[str] = []

        def checkbox_field(label: str, default: bool) -> object:
            checkbox_fields.append(label)
            return SimpleNamespace(result=label.startswith("Incremental"))

        with (
            patch.object(plugin, "DirectoryNameField", lambda label, default_name: SimpleNamespace(result=str(output_dir))),
            patch.object(plugin, "CheckboxField", checkbox_field),
            patch.object(plugin, "IntegerField", integer_field),
            patch.object(plugin, "get_form_input", return_value=True),
        ):
            cfg = plugin._prompt_export_config(bv)

        self.assertIsNotNone(cfg)
        assert cfg is not None
        self.assertEqual(cfg.function_time_limit_seconds, 901)
        self.assertEqual(cfg.private_memory_limit_gib, 25)
        self.assertTrue(cfg.incremental)
        self.assertIn("Incremental export (unchecked = full export; reuse successful functions)", checkbox_fields)
        self.assertEqual(
            integer_fields,
            [
                ("Function analysis/export time limit (seconds)", 900),
                ("Per-function PrivateUsage ceiling (GiB)", 24),
            ],
        )

    def test_skip_does_not_mark_the_function_when_halt_request_fails(self) -> None:
        import binja_no_mcp.plugin as plugin

        bv = self._executable_view()
        function = bv.functions[0]

        class WorkflowMachine:
            def halt(self) -> dict[str, object]:
                return {"commandStatus": {"accepted": False}}

        function.workflow = SimpleNamespace(machine=WorkflowMachine())
        task = SimpleNamespace()
        function_key = (function.start, "aarch64")
        plugin._register_active_task(bv, task)
        plugin._set_current_function(task, function_key, function)

        try:
            with (
                patch.object(plugin, "execute_on_main_thread", lambda callback: callback()),
                patch.object(plugin, "log_error"),
            ):
                plugin._skip_current_function(bv)
            self.assertFalse(plugin._skip_requested_for(task, function_key))
            self.assertFalse(plugin._finish_current_function(task, function_key))
        finally:
            plugin._unregister_active_task(bv, task)

    def test_memory_ceiling_halt_ignores_a_function_that_already_finished(self) -> None:
        import binja_no_mcp.plugin as plugin

        bv = self._executable_view()
        function = bv.functions[0]
        function_key = (function.start, "aarch64")
        callbacks: list[object] = []

        class WorkflowMachine:
            def __init__(self) -> None:
                self.halt_calls = 0

            def halt(self) -> None:
                self.halt_calls += 1

        machine = WorkflowMachine()
        function.workflow = SimpleNamespace(machine=machine)
        task = SimpleNamespace()
        plugin._set_current_function(task, function_key, function)

        with patch.object(plugin, "execute_on_main_thread", callbacks.append):
            plugin._request_memory_ceiling_halt(task, function_key, function)

        plugin._finish_current_function(task, function_key)
        self.assertEqual(len(callbacks), 1)
        callbacks[0]()
        self.assertEqual(machine.halt_calls, 0)

    def test_abort_binary_view_analysis_requires_yes_confirmation(self) -> None:
        import binja_no_mcp.plugin as plugin

        bv = self._executable_view()
        calls: list[None] = []
        bv.abort_analysis = lambda: calls.append(None)

        with patch.object(plugin, "show_message_box", return_value=plugin.MessageBoxButtonResult.NoButton):
            plugin._abort_binary_view_analysis(bv)
        self.assertEqual(calls, [])

        with patch.object(plugin, "show_message_box", return_value=plugin.MessageBoxButtonResult.YesButton):
            plugin._abort_binary_view_analysis(bv)
        self.assertEqual(calls, [None])


if __name__ == "__main__":
    unittest.main()
