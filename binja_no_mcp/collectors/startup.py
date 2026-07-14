from __future__ import annotations

import struct

from ..naming import function_id


EM_AARCH64 = 183
ET_EXEC = 2
ET_DYN = 3
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
DT_NULL = 0
DT_INIT = 12
DT_SONAME = 14
DT_INIT_ARRAY = 25
DT_INIT_ARRAYSZ = 27
DT_PREINIT_ARRAY = 32
DT_PREINIT_ARRAYSZ = 33
DT_FLAGS_1 = 0x6FFFFFFB
DF_1_PIE = 0x08000000


def _read_raw(bv: object, offset: int, length: int) -> bytes:
    raw = getattr(getattr(bv, "file", None), "raw", None)
    read = getattr(raw, "read", None)
    if not callable(read) or offset < 0 or length < 0:
        return b""
    try:
        return bytes(read(offset, length))
    except Exception:
        return b""


def _parse_elf64(bv: object) -> dict[str, object] | None:
    header = _read_raw(bv, 0, 64)
    if len(header) != 64 or header[:4] != b"\x7fELF" or header[4] != 2 or header[5] not in {1, 2}:
        return None
    endian = "<" if header[5] == 1 else ">"
    try:
        fields = struct.unpack(f"{endian}16sHHIQQQIHHHHHH", header)
    except struct.error:
        return None
    elf_type, machine, entry = fields[1], fields[2], fields[4]
    phoff, phentsize, phnum = fields[5], fields[9], fields[10]
    if machine != EM_AARCH64 or phentsize < 56 or not 0 < phnum <= 4096:
        return None

    load_segments: list[tuple[int, int, int]] = []
    dynamic_segments: list[tuple[int, int]] = []
    has_interp = False
    for index in range(phnum):
        data = _read_raw(bv, phoff + index * phentsize, 56)
        if len(data) != 56:
            return None
        try:
            kind, _, offset, vaddr, _, filesz, _, _ = struct.unpack(f"{endian}IIQQQQQQ", data)
        except struct.error:
            return None
        if kind == PT_LOAD:
            load_segments.append((vaddr, offset, filesz))
        elif kind == PT_DYNAMIC:
            dynamic_segments.append((offset, filesz))
        elif kind == PT_INTERP:
            has_interp = True

    tags: dict[int, list[int]] = {}
    for offset, size in dynamic_segments:
        if size > 1 << 20:
            continue
        data = _read_raw(bv, offset, size)
        for position in range(0, len(data) - 15, 16):
            tag, value = struct.unpack_from(f"{endian}qQ", data, position)
            if tag == DT_NULL:
                break
            tags.setdefault(tag, []).append(value)

    return {
        "endian": endian,
        "elf_type": elf_type,
        "entry": entry,
        "load_segments": load_segments,
        "has_interp": has_interp,
        "tags": tags,
    }


def _first_tag(tags: dict[int, list[int]], tag: int) -> int | None:
    values = tags.get(tag, [])
    return values[0] if values else None


def _read_array(bv: object, elf: dict[str, object], address: int | None, size: int | None) -> list[int]:
    if address is None or size is None or size <= 0 or size > 1 << 20:
        return []
    read = getattr(bv, "read", None)
    if not callable(read):
        return []
    data = bytes(read(_load_bias(bv, elf) + address, size))
    return [struct.unpack_from(f"{elf['endian']}Q", data, index)[0] for index in range(0, len(data) - 7, 8)]


def _load_bias(bv: object, elf: dict[str, object]) -> int:
    entry = int(elf["entry"])
    entry_point = getattr(bv, "entry_point", None)
    if entry and entry_point is not None:
        try:
            return int(entry_point) - entry
        except (TypeError, ValueError):
            pass
    start = getattr(bv, "start", None)
    load_segments = elf["load_segments"]
    if start is not None and load_segments:
        try:
            minimum_vaddr = min(segment[0] for segment in load_segments)
            if int(start) >= minimum_vaddr:
                return int(start) - minimum_vaddr
        except (TypeError, ValueError):
            pass
    return 0


def _symbol_start(functions: list[object], name: str) -> int | None:
    for function in functions:
        symbol = getattr(function, "symbol", None)
        for attribute in ("raw_name", "short_name", "full_name"):
            if getattr(symbol, attribute, None) == name:
                try:
                    return int(getattr(function, "start"))
                except (TypeError, ValueError):
                    return None
    return None


def _constant(expression: object) -> int | None:
    try:
        value = getattr(expression, "constant", None)
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _operation_name(instruction: object) -> str:
    operation = getattr(instruction, "operation", None)
    return str(getattr(operation, "name", operation) or "")


def _bionic_main(functions: list[object], known_function_starts: set[int], entry_start: int) -> int | None:
    libc_init = _symbol_start(functions, "__libc_init")
    if libc_init is None:
        return None
    for function in functions:
        if getattr(function, "start", None) != entry_start:
            continue
        try:
            mlil = getattr(function, "medium_level_il", None)
        except Exception:
            continue
        for instruction in getattr(mlil, "instructions", []) if mlil is not None else []:
            if _operation_name(instruction) not in {"MLIL_CALL", "MLIL_TAILCALL"}:
                continue
            if _constant(getattr(instruction, "dest", None)) != libc_init:
                continue
            params = getattr(instruction, "params", [])
            if len(params) < 3:
                continue
            candidate = _constant(params[2])
            if candidate in known_function_starts:
                return candidate
    return None


def _target_kind(elf: dict[str, object]) -> str:
    elf_type = elf["elf_type"]
    tags = elf["tags"]
    if elf_type == ET_EXEC:
        return "executable"
    if elf_type != ET_DYN:
        return "unknown"
    flags_1 = _first_tag(tags, DT_FLAGS_1) or 0
    is_pie = elf["has_interp"] or flags_1 & DF_1_PIE
    if is_pie and _first_tag(tags, DT_SONAME) is not None:
        return "unknown"
    if is_pie:
        return "pie"
    return "shared_library"


def collect_startup_entries(bv: object, known_function_starts: set[int]) -> dict[str, object]:
    elf = _parse_elf64(bv)
    if elf is None:
        return {"target_kind": "unknown", "entries": []}

    target_kind = _target_kind(elf)
    if target_kind == "unknown" and elf["elf_type"] != ET_DYN:
        return {"target_kind": target_kind, "entries": []}
    tags = elf["tags"]
    bias = _load_bias(bv, elf)
    entries: list[dict[str, str]] = []

    def add(address: int | None, stage: str) -> None:
        if address is None or address == 0:
            return
        add_actual(bias + address, stage)

    def add_actual(actual_address: int | None, stage: str) -> None:
        if actual_address is None or actual_address == 0:
            return
        entries.append({"id": function_id(actual_address), "stage": stage})

    if target_kind in {"executable", "pie"}:
        for address in _read_array(
            bv,
            elf,
            _first_tag(tags, DT_PREINIT_ARRAY),
            _first_tag(tags, DT_PREINIT_ARRAYSZ),
        ):
            add_actual(address, "preinit_array")

    add(_first_tag(tags, DT_INIT), "init")
    for address in _read_array(bv, elf, _first_tag(tags, DT_INIT_ARRAY), _first_tag(tags, DT_INIT_ARRAYSZ)):
        add_actual(address, "init_array")

    functions = list(getattr(bv, "functions", []))
    if target_kind in {"executable", "pie"}:
        entry_start = bias + int(elf["entry"])
        add(int(elf["entry"]), "elf_entry")
        main = _symbol_start(functions, "main")
        add_actual(main if main is not None else _bionic_main(functions, known_function_starts, entry_start), "main")
    elif target_kind == "shared_library":
        add_actual(_symbol_start(functions, "JNI_OnLoad"), "jni_on_load")

    return {"target_kind": target_kind, "entries": entries}
