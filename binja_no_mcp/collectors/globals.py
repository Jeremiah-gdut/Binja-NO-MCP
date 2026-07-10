from __future__ import annotations

from ..naming import hex_addr


def _enum_name(value: object) -> str | None:
    if value is None:
        return None
    return str(getattr(value, "name", value))


def _type_name(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def collect_binary_metadata(
    bv: object,
    function_count: int,
    *,
    snapshot_status: str = "partial",
    exported_function_count: int = 0,
    failed_function_count: int = 0,
) -> dict[str, object]:
    file_metadata = getattr(bv, "file", None)
    arch = getattr(bv, "arch", None)
    platform = getattr(bv, "platform", None)
    return {
        "schema_version": 1,
        "snapshot_status": snapshot_status,
        "planned_function_count": function_count,
        "exported_function_count": exported_function_count,
        "failed_function_count": failed_function_count,
        "function_index_file": "meta/function_index.jsonl",
        "startup_entries_file": "meta/startup_entries.json",
        "filename": getattr(file_metadata, "filename", None),
        "view_type": getattr(bv, "view_type", None),
        "start": hex_addr(getattr(bv, "start", None)),
        "end": hex_addr(getattr(bv, "end", None)),
        "entry_point": hex_addr(getattr(bv, "entry_point", None)),
        "arch": getattr(arch, "name", None),
        "platform": getattr(platform, "name", None),
        "function_count": function_count,
    }


def collect_string_records(bv: object) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for string_ref in getattr(bv, "strings", []):
        records.append(
            {
                "address": hex_addr(getattr(string_ref, "start", None)),
                "type": _enum_name(getattr(string_ref, "type", None)),
                "length": getattr(string_ref, "length", None),
                "value": getattr(string_ref, "value", None),
            }
        )
    return sorted(records, key=lambda record: record["address"] or "")


def collect_data_var_records(bv: object) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    data_vars = getattr(bv, "data_vars", {})
    for address, data_var in sorted(data_vars.items()):
        symbol = None
        get_symbol_at = getattr(bv, "get_symbol_at", None)
        if get_symbol_at is not None:
            symbol = get_symbol_at(address)
        records.append(
            {
                "address": hex_addr(address),
                "type": _type_name(getattr(data_var, "type", None)),
                "name": getattr(symbol, "short_name", None) or getattr(symbol, "raw_name", None),
            }
        )
    return records


def collect_section_records(bv: object) -> list[dict[str, object]]:
    sections = getattr(bv, "sections", {})
    records: list[dict[str, object]] = []
    for name, section in sorted(sections.items(), key=lambda item: getattr(item[1], "start", 0)):
        start = getattr(section, "start", None)
        length = getattr(section, "length", None)
        end = getattr(section, "end", None)
        if end is None and start is not None and length is not None:
            end = int(start) + int(length)
        records.append(
            {
                "name": name,
                "start": hex_addr(start),
                "end": hex_addr(end),
                "length": length,
                "semantics": _enum_name(getattr(section, "semantics", None)),
                "type": getattr(section, "type", None),
                "align": getattr(section, "align", None),
                "entry_size": getattr(section, "entry_size", None),
            }
        )
    return records


def collect_segment_records(bv: object) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for segment in sorted(getattr(bv, "segments", []), key=lambda seg: getattr(seg, "start", 0)):
        start = getattr(segment, "start", None)
        end = getattr(segment, "end", None)
        records.append(
            {
                "start": hex_addr(start),
                "end": hex_addr(end),
                "length": None if start is None or end is None else int(end) - int(start),
                "data_offset": getattr(segment, "data_offset", None),
                "data_length": getattr(segment, "data_length", None),
                "readable": getattr(segment, "readable", None),
                "writable": getattr(segment, "writable", None),
                "executable": getattr(segment, "executable", None),
                "auto_defined": getattr(segment, "auto_defined", None),
            }
        )
    return records


def collect_symbol_records(bv: object) -> list[dict[str, object]]:
    symbol_mapping = getattr(bv, "symbols", {})
    records: list[dict[str, object]] = []
    seen: set[tuple[int | None, str | None, str | None]] = set()
    for symbol_list in symbol_mapping.values():
        for symbol in symbol_list:
            key = (
                getattr(symbol, "address", None),
                getattr(symbol, "raw_name", None),
                _enum_name(getattr(symbol, "type", None)),
            )
            if key in seen:
                continue
            seen.add(key)
            records.append(
                {
                    "address": hex_addr(getattr(symbol, "address", None)),
                    "type": _enum_name(getattr(symbol, "type", None)),
                    "raw_name": getattr(symbol, "raw_name", None),
                    "short_name": getattr(symbol, "short_name", None),
                    "full_name": getattr(symbol, "full_name", None),
                }
            )
    return sorted(records, key=lambda record: (record["address"] or "", record["raw_name"] or ""))
