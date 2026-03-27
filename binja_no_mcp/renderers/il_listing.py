from __future__ import annotations


def _format_prefix(instruction: object) -> str:
    parts: list[str] = []
    address = getattr(instruction, "address", None)
    if isinstance(address, int):
        parts.append(f"0x{address:016x}")
    instr_index = getattr(instruction, "instr_index", None)
    expr_index = getattr(instruction, "expr_index", None)
    if instr_index is not None:
        parts.append(f"i{instr_index}")
    elif expr_index is not None:
        parts.append(f"e{expr_index}")
    return " ".join(parts)


def render_il_listing(il_function: object) -> str:
    basic_blocks = getattr(il_function, "basic_blocks", None) or il_function
    lines: list[str] = []
    for block_index, block in enumerate(basic_blocks):
        start = getattr(block, "start", None)
        end = getattr(block, "end", None)
        if start is not None and end is not None:
            lines.append(f"# block {block_index} [{start}, {end})")
        else:
            lines.append(f"# block {block_index}")
        for instruction in block:
            prefix = _format_prefix(instruction)
            text = str(instruction)
            lines.append(f"{prefix}: {text}" if prefix else text)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
