from __future__ import annotations

from .il_listing import render_il_listing


def render_hlil(hlil: object, declaration: str | None = None) -> str:
    body = render_il_listing(hlil)
    if not declaration:
        return body
    return f"// declaration: {declaration}\n\n{body}"
