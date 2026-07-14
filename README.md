# Binja-NO-MCP
Author: **Jeremiah**

Export the current Binary Ninja `BinaryView` into a stable on-disk tree for AI IDE workflows.

## Scope

Current UI workflow:

- exports function artifacts only for the function set frozen from `bv.functions`
- keeps the exporter read-only
- freezes the recognized function set before export scheduling
- reanalyzes each frozen function and exports it immediately after its analysis completes by default
- lets you choose the output directory manually in a form
- supports a full replacement export or an incremental export that retries only unfinished functions in an existing snapshot
- exports raw HLIL linear-view text by default
- preserves address comments from the current analysis view in exported linear HLIL / pseudo-C when available
- lets you choose pseudo-C / MLIL / MLIL SSA / LLIL as optional exports in the UI
- writes the function declaration into the exported HLIL header and `.meta.json`
- writes a current-snapshot header, startup entries, and a compact function index

## Output Layout

```text
binja-no-mcp-export/
  meta/
    binary.json
    export_config.json
    failures.jsonl
    function_index.jsonl
    startup_entries.json
    sections.json
    segments.json
  functions/
    main.hlil.txt
    main.meta.json
  data/
    strings.jsonl
    data_vars.jsonl
    symbols.jsonl
  optional/
    pseudoc/
      main.pseudoc.c
    mlil/
      main.mlil.txt
    mlil_ssa/
      main.mlil_ssa.txt
    llil/
      main.llil.txt
```

## UI Usage

1. Open the sample in Binary Ninja and let the analysis state settle to exactly what you want to export.
2. Run `Plugins -> Export for AI`.
3. In the form, choose the output directory and either full export (the default) or incremental export.
4. Select which IL layers to export.

Defaults:

- Reanalyze before export: enabled
- Incremental export: disabled (full replacement export)
- HLIL: enabled
- pseudo-C: disabled
- MLIL: disabled
- MLIL SSA: disabled
- LLIL: disabled

Enabled by the default configuration:

- `*.meta.json`
- `meta/function_index.jsonl`
- `meta/startup_entries.json`
- `meta/failures.jsonl`
- `meta/binary.json`
- `meta/export_config.json`
- `meta/sections.json`
- `meta/segments.json`
- `data/strings.jsonl`
- `data/data_vars.jsonl`
- `data/symbols.jsonl`

`meta/binary.json` is the snapshot header. Read it first for schema, status, and function counts. For open-ended program analysis, read startup entries next and query matching function-index records. A user-specified function can go directly to its index record; a pure metadata question can go directly to the relevant metadata artifact after the header. A full export replaces the previous snapshot. Incremental export requires the same target snapshot, reuses only functions already marked exported with all selected artifacts present, and retries every other function.

## Notes

- The exporter never adds functions, entry points, sections, symbols, or refs.
- The UI command serializes `reanalyze current function -> analysis completion -> export current function`.
- `run_export` itself does not call `update_analysis_and_wait()`.
- Optional pseudo-C / MLIL / MLIL SSA / LLIL exports are only generated when you explicitly enable them in the form.
- Startup arrays are read from the relocation-applied BinaryView. Their nonzero slots retain order and duplicates even when Binary Ninja has no function artifact for an address.
- Function artifact filenames use their sanitized Binary Ninja function names; unnamed functions use `sub_<offset>`.
- The PrivateUsage ceiling is evaluated per function window: a crossing skips that function and then allows the next one to run.

## Development Notes

Project layout follows the requested split:

- `binja_no_mcp/config.py`
- `binja_no_mcp/collectors/`
- `binja_no_mcp/renderers/`
- `binja_no_mcp/exporters/`
- `binja_no_mcp/models/`
- `binja_no_mcp/plugin.py`

## License

This plugin is released under the [MIT license](./LICENSE).
