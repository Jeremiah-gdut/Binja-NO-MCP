# Binja-NO-MCP
Author: **Jeremiah**

Export the current Binary Ninja `BinaryView` into a stable on-disk tree for AI IDE workflows.

## Scope

Current UI workflow:

- exports only `bv.functions`
- keeps the exporter read-only
- freezes the recognized function set before export scheduling
- reanalyzes each frozen function and exports it immediately after its analysis completes by default
- lets you choose the output directory manually in a form
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
    0x88504.hlil.txt
    0x88504.meta.json
  data/
    strings.jsonl
    data_vars.jsonl
    symbols.jsonl
  optional/
    pseudoc/
      0x88504.pseudoc.c
    mlil/
      0x88504.mlil.txt
    mlil_ssa/
      0x88504.mlil_ssa.txt
    llil/
      0x88504.llil.txt
```

## UI Usage

1. Open the sample in Binary Ninja and let the analysis state settle to exactly what you want to export.
2. Run `Plugins -> Export for AI`.
3. In the form, choose the output directory.
4. Select which IL layers to export.

Defaults:

- Reanalyze before export: enabled
- HLIL: enabled
- pseudo-C: disabled
- MLIL: disabled
- MLIL SSA: disabled
- LLIL: disabled

Always exported:

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

`meta/binary.json` is the snapshot header. Read it first for schema, status, and function counts; then read startup entries and the function index. A new export replaces the previous snapshot.

## Notes

- The exporter never adds functions, entry points, sections, symbols, or refs.
- The UI command serializes `reanalyze current function -> analysis completion -> export current function`.
- `run_export` itself does not call `update_analysis_and_wait()`.
- Optional pseudo-C / MLIL / MLIL SSA / LLIL exports are only generated when you explicitly enable them in the form.

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
