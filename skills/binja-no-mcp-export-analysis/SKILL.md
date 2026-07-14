---
name: binja-no-mcp-export-analysis
description: Navigate Binja-NO-MCP snapshots from information needs to exact artifacts and evidence.
---

# Binja-no-mcp Export Analysis

Treat the export snapshot as an evidence map. Resolve paths relative to the snapshot root.

## Navigate the snapshot

1. Read `meta/binary.json` first. Record `schema_version`, `snapshot_status`, target identity, and function counts. A `partial` or `cancelled` snapshot supports positive findings only; a missing record is not evidence of absence. This step is complete when the snapshot's identity and evidence boundary are explicit.
2. Choose the analysis branch:
   - For a user-specified function, query only its matching `id`, `name`, or `declaration` record in `meta/function_index.jsonl`, then follow that record's `artifacts` paths.
   - For a pure metadata question, open the routed metadata artifact after the header. Address-to-segment or address-to-section questions do not require function bodies.
   - For open-ended program analysis, read `meta/startup_entries.json` before any other function body. Resolve every listed `id` against `meta/function_index.jsonl` in order and preserve duplicate startup slots. For an indexed entry, read `artifacts.meta` and then `artifacts.hlil` when present. Record an unmatched entry, or an indexed entry without artifacts, as a confirmed startup address with no readable function artifact. This branch is complete when every startup entry is accounted for as readable or artifact-less.
3. Use the routing table below. Read [references/artifacts.md](references/artifacts.md) before interpreting fields, joining artifacts, making absence claims, or reading bytes from the original binary. This step is complete when every claim points to the routed artifact and field.
4. Expand callees, optional IL, or raw bytes only when the current question requires them. Keep exported snapshot evidence, Binary Ninja analysis evidence, and raw-file evidence distinct in the answer.

## Routing table

| Information need | Artifact | Inspect or filter |
| --- | --- | --- |
| Schema, snapshot status, target, counts | `meta/binary.json` | `schema_version`, `snapshot_status`, target fields, function counts |
| Enabled export options | `meta/export_config.json` | `export_*`, `write_failures`, `incremental`, limits |
| Export failures | `meta/failures.jsonl` | `phase`, `start`, `reason`, `error` |
| Startup route | `meta/startup_entries.json` | `target_kind`, ordered `entries[].stage`, `entries[].id` |
| Function by name or address | `meta/function_index.jsonl` | match `id`, `name`, or `declaration`; inspect `export_status` and `artifacts` |
| Prototype, calling convention, return behavior | index `artifacts.meta` | `prototype`, `calling_convention`, `can_return` |
| Outbound calls and call sites | source function meta | `call_evidence[]` |
| Callers of a target | all exported function metas | records where `call_evidence[].target` equals the target `id` |
| Decompiled body or comments | index `artifacts` | `hlil` first; optional `pseudoc`, `mlil`, `mlil_ssa`, or `llil` only when needed |
| Strings | `data/strings.jsonl` | `address`, `type`, `length`, `value` |
| Data variables | `data/data_vars.jsonl` | `address`, `type`, `name` |
| Symbols, imports, exports | `data/symbols.jsonl` | classify `type`; inspect names and `address` |
| Address range, RWX, file backing | `meta/segments.json` | containing range, permissions, `data_offset`, `data_length` |
| Section name and semantics | `meta/sections.json` | containing range, `name`, `semantics`, `type` |
| Bytes absent from the snapshot | original binary after segment lookup | map only the file-backed segment range and label the result raw-file evidence |
