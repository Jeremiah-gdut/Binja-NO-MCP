from __future__ import annotations

from .il_listing import render_il_listing
from .linear_text import format_unaddressed_text, render_linear_lines


def _with_declaration(body: str, declaration: str | None) -> str:
    if not declaration:
        return body
    return f"{format_unaddressed_text(f'// declaration: {declaration}')}\n{body}"


def _render_hlil_linear(hlil: object, declaration: str | None) -> str:
    root = getattr(hlil, "root", None)
    if root is None:
        return _with_declaration(render_il_listing(hlil, inline_addresses=True), declaration)
    get_lines = getattr(root, "get_lines", None)
    if not callable(get_lines):
        return _with_declaration(render_il_listing(hlil, inline_addresses=True), declaration)

    lines = get_lines()
    prefix_lines = (f"// declaration: {declaration}", "") if declaration else ()
    rendered = render_linear_lines(lines, getattr(hlil, "source_function", None), prefix_lines).rstrip()
    if not rendered:
        return _with_declaration(render_il_listing(hlil, inline_addresses=True), declaration)
    return rendered + "\n"


def render_hlil(hlil: object, declaration: str | None = None) -> str:
    return _render_hlil_linear(hlil, declaration)
