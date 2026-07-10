from __future__ import annotations

from .linear_text import format_linear_line


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


def _instruction_index_prefix(instruction: object) -> str:
    instr_index = getattr(instruction, "instr_index", None)
    expr_index = getattr(instruction, "expr_index", None)
    if instr_index is not None:
        return f"i{instr_index}"
    if expr_index is not None:
        return f"e{expr_index}"
    return ""


def render_il_listing(il_function: object, inline_addresses: bool = False) -> str:
    basic_blocks = getattr(il_function, "basic_blocks", None) or il_function
    lines: list[str] = []
    for block_index, block in enumerate(basic_blocks):
        start = getattr(block, "start", None)
        end = getattr(block, "end", None)
        if start is not None and end is not None:
            block_text = f"# block {block_index} [{start}, {end})"
        else:
            block_text = f"# block {block_index}"
        lines.append(format_linear_line(block_text) if inline_addresses else block_text)
        for instruction in block:
            text = str(instruction)
            if inline_addresses:
                address = getattr(instruction, "address", None)
                instruction_prefix = _instruction_index_prefix(instruction)
                lines.append(
                    format_linear_line(
                        f"{instruction_prefix}: {text}" if instruction_prefix else text,
                        address if isinstance(address, int) else None,
                    )
                )
            else:
                prefix = _format_prefix(instruction)
                lines.append(f"{prefix}: {text}" if prefix else text)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
