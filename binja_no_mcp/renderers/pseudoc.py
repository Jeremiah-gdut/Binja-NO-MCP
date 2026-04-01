from __future__ import annotations

from .linear_text import render_linear_lines

PSEUDO_C_ATTRIBUTE = "pseudo_c_if_available"
LANGUAGE_REPRESENTATION_ATTRIBUTE = "language_representation_if_available"


def _fallback_pseudoc(hlil: object) -> str:
    instructions = getattr(hlil, "instructions", None)
    if instructions is None:
        return f"{hlil}\n"
    lines = [str(instruction) for instruction in instructions]
    return "\n".join(lines).rstrip() + "\n"


def _prepend_declaration(body: str, declaration: str | None) -> str:
    if not declaration:
        return body
    return f"{declaration}\n{body.lstrip()}"


def render_pseudoc(hlil: object, declaration: str | None = None) -> str:
    func = getattr(hlil, "source_function", None)
    if func is None:
        return _prepend_declaration(_fallback_pseudoc(hlil), declaration)

    renderer = getattr(func, PSEUDO_C_ATTRIBUTE, None) or getattr(func, LANGUAGE_REPRESENTATION_ATTRIBUTE, None)
    if renderer is None:
        return _prepend_declaration(_fallback_pseudoc(hlil), declaration)

    root = getattr(hlil, "root", None)
    if root is None:
        return _prepend_declaration(_fallback_pseudoc(hlil), declaration)

    lines = renderer.get_linear_lines(root)
    rendered = render_linear_lines(lines, func).rstrip()
    return _prepend_declaration(rendered + "\n", declaration)
