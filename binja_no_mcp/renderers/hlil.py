from __future__ import annotations

from .il_listing import render_il_listing
from .linear_text import render_linear_lines


def _render_hlil_linear(hlil: object) -> str:
    root = getattr(hlil, "root", None)
    if root is None:
        return render_il_listing(hlil)
    get_lines = getattr(root, "get_lines", None)
    if not callable(get_lines):
        return render_il_listing(hlil)

    lines = get_lines()
    rendered = render_linear_lines(lines, getattr(hlil, "source_function", None)).rstrip()
    if not rendered:
        return render_il_listing(hlil)
    return rendered + "\n"


def render_hlil(hlil: object, declaration: str | None = None) -> str:
    body = _render_hlil_linear(hlil)
    if not declaration:
        return body
    return f"// declaration: {declaration}\n\n{body}"
