# Export artifact reference

All paths are relative to the snapshot root. Artifact presence depends on `meta/export_config.json`, export progress, and per-function success.

## Snapshot and routing metadata

### `meta/binary.json`

The snapshot header contains:

- `schema_version`
- `snapshot_status`: `complete`, `partial`, or `cancelled`
- `planned_function_count`, `exported_function_count`, `failed_function_count`, `function_count`
- `function_index_file`, `startup_entries_file`
- `filename`, `view_type`, `start`, `end`, `entry_point`, `arch`, `platform`

`complete` means every function frozen at export start was exported and no failure was recorded. It does not mean every global artifact was enabled. Use `meta/export_config.json` to establish coverage.

### `meta/export_config.json`

Use `export_hlil`, `export_pseudoc`, `export_mlil`, `export_mlil_ssa`, `export_llil`, `export_strings`, `export_data_vars`, `export_sections`, `export_segments`, and `export_symbols` to determine requested coverage. The remaining fields are `output_dir`, `reanalyze_before_export`, `batch_size`, `overwrite`, `write_failures`, `function_time_limit_seconds`, `private_memory_limit_gib`, and `incremental`.

### `meta/failures.jsonl`

Each record has `start`, `name`, `phase`, and `error`; it may also have `reason`, `elapsed_seconds`, and `memory_window`. A null `start` identifies a global-phase failure. The file can be absent when `write_failures` is false.

### `meta/startup_entries.json`

The object contains `target_kind` and ordered `entries`. `target_kind` is `executable`, `pie`, `shared_library`, or `unknown`. Every entry is `{ "id": "0x...", "stage": "..." }`; stages are `preinit_array`, `init`, `init_array`, `elf_entry`, `main`, and `jni_on_load`.

Treat the entries as confirmed startup addresses, not a complete execution trace. Array slot order and duplicate slots are evidence and remain in the list. An `id` can be absent from the function index when Binary Ninja did not recognize a function at that address. `target_kind: "unknown"` or an empty list is not proof that the target has no startup entry.

### `meta/function_index.jsonl`

Each function record contains `id`, `name`, `declaration`, `artifacts`, `export_status`, `export_error`, and `startup_stages`; `memory_window` is optional. `export_status` is `exported`, `partial`, `failed`, or `not_exported`. Query by the unpadded function `id` or by `name`, then use the paths in `artifacts`; never derive an artifact filename from the function name.

`startup_stages` is the unique set of stages associated with an indexed function. It intentionally differs from the ordered, duplicate-preserving startup entry list.

## Function artifacts

The index's `artifacts.meta` file contains:

- identity: `id`, `start`, `name`, `raw_name`, `sanitized_name`, `symbol_name`
- signature: `declaration`, `prototype`, `calling_convention`, `can_return`
- availability: `hlil_available`, `hlil_file`, `pseudoc_file`, `mlil_file`, `mlil_ssa_file`, `llil_file`
- evidence and status: `call_evidence`, `export_error`

`prototype` contains `return_type`, `parameters`, `parameter_count`, and `has_variable_arguments`. Parameter records contain `index`, `name`, `raw_name`, `type`, and `location`.

Follow `artifacts.hlil` for the default body. Follow `artifacts.pseudoc`, `artifacts.mlil`, `artifacts.mlil_ssa`, or `artifacts.llil` only when the key exists and that representation answers the question better. A configured representation can still be absent for an individual failed or partial function.

HLIL and pseudo-C lines use Binary Ninja virtual addresses when a source address is available. Addressless lines remain addressless; do not inherit a neighboring line's address.

## Call joins

`call_evidence` lives in the source function meta:

- `direct_il`: a direct constant LLIL call or tail call with `call_site` and `target`
- `bn_analysis`: a Binary Ninja analysis reference with `call_site` and `target`, useful for navigation
- `unresolved_indirect`: an indirect call with `call_site` and no known `target`

For outbound calls, inspect the current source meta. For callers, scan exported source metas and select evidence whose `target` equals the target function `id`. A target can be absent from the function index. Missing evidence does not rule out runtime-computed indirect calls.

## Global data artifacts

| Artifact | Record fields | Boundary |
| --- | --- | --- |
| `data/strings.jsonl` | `address`, `type`, `length`, `value` | Binary Ninja-recognized strings only |
| `data/data_vars.jsonl` | `address`, `type`, `name` | Binary Ninja-recognized data variables; `name` can be null |
| `data/symbols.jsonl` | `address`, `type`, `raw_name`, `short_name`, `full_name` | classify imports and exports by `type`; no binding field |
| `meta/sections.json` | `name`, `start`, `end`, `length`, `semantics`, `type`, `align`, `entry_size` | Binary Ninja section view; stripped-target names are auxiliary evidence |
| `meta/segments.json` | `start`, `end`, `length`, `data_offset`, `data_length`, `readable`, `writable`, `executable`, `auto_defined` | Binary Ninja mapped ranges and file backing; no segment bytes |

## Raw-byte fallback

The snapshot does not copy data-segment bytes. When the original binary is available, read an address as follows:

1. Find a segment where `start <= address < start + data_length`.
2. Compute `file_offset = data_offset + (address - start)` using numeric values of the hexadecimal addresses.
3. Bound the read to the segment's `data_length` and the original file.

The range from `start + data_length` to `end` can be zero-filled memory such as BSS and has no corresponding original-file bytes. Raw-file bytes do not include Binary Ninja's relocation-applied mapped values. Label conclusions from this fallback as raw-file evidence and keep them separate from snapshot evidence. If the original binary is unavailable, report that the requested bytes are outside the snapshot's coverage.

## Trust and address rules

- Use a `complete` snapshot plus enabled-artifact coverage before making a global absence claim. In `partial` or `cancelled` snapshots, positive records remain useful while missing records remain unknown.
- Treat `direct_il` as verified direct-call evidence, `bn_analysis` as navigation evidence, and `unresolved_indirect` as an explicitly unknown target.
- Function and startup IDs are lowercase, unpadded hexadecimal. Global addresses and section or segment bounds are 16-digit hexadecimal strings. Lengths and file offsets are integers.
- The snapshot has no global call graph, string-xref index, raw data-segment copy, or query script.
