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
            self.assertEqual(main["artifacts"]["hlil"], "functions/0x101000.hlil.txt")
            self.assertIn("elf_entry", main["startup_stages"])
            self.assertIn("main", main["startup_stages"])
            self.assertNotIn("call_evidence", main)

            meta = json.loads((output_dir / "functions" / "0x101000.meta.json").read_text(encoding="utf-8"))
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
            self.assertTrue((output_dir / "functions" / "0x101000.hlil.txt").exists())
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
            rendered = (output_dir / "functions" / "0x88504.hlil.txt").read_text(encoding="utf-8")
            pseudoc = (output_dir / "optional" / "pseudoc" / "0x88504.pseudoc.c").read_text(encoding="utf-8")

        self.assertIn("0x88504", rendered)
        self.assertIn("note", rendered)
        self.assertIn("                  {", rendered)
        self.assertIn("                  // declaration: int f(void)", rendered)
        self.assertIn("\n                  \n", rendered)
        self.assertNotIn("0x0000000000088504", rendered)
        self.assertIn("0x88508", pseudoc)
        self.assertIn("                  {", pseudoc)

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
        with (
            patch.object(plugin, "execute_on_main_thread_and_wait", lambda callback: callback()),
            patch.object(plugin, "execute_on_main_thread", lambda callback: callback()),
            patch.object(plugin, "_show_completion"),
        ):
            plugin._ExportTask.run(task)

        self.assertTrue(any("main" in progress for progress in task.history))
        self.assertTrue(any("0x101200" in progress for progress in task.history))
        self.assertNotIn("main", task.history[-1])
        self.assertNotIn("0x101200", task.history[-1])

        cancelled = TaskSurrogate()

        def cancel_after_first_export(session: object, view: object, function_key: object) -> None:
            cancelled.cancelled = True

        with (
            patch.object(plugin, "execute_on_main_thread_and_wait", lambda callback: callback()),
            patch.object(plugin, "execute_on_main_thread", lambda callback: callback()),
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


if __name__ == "__main__":
    unittest.main()
