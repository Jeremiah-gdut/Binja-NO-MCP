from __future__ import annotations

from .linear_text import format_unaddressed_text, render_linear_lines

PSEUDO_C_ATTRIBUTE = "pseudo_c_if_available"
LANGUAGE_REPRESENTATION_ATTRIBUTE = "language_representation_if_available"


def _fallback_pseudoc(hlil: object) -> str:
    instructions = getattr(hlil, "instructions", None)
    if instructions is None:
        return format_unaddressed_text(str(hlil))
    lines = [str(instruction) for instruction in instructions]
    return format_unaddressed_text("\n".join(lines))


def _prepend_declaration(body: str, declaration: str | None) -> str:
    if not declaration:
        return body
    return f"{format_unaddressed_text(declaration)}{body}"


def render_pseudoc(hlil: object, declaration: str | None = None) -> str:
    func = getattr(hlil, "source_function", None)
    if func is None:
        return _prepend_declaration(_fallback_pseudoc(hlil), declaration)

    renderer = getattr(func, PSEUDO_C_ATTRIBUTE, None)
    if renderer is None:
        get_representation = getattr(func, LANGUAGE_REPRESENTATION_ATTRIBUTE, None)
        if callable(get_representation):
            try:
                renderer = get_representation("Pseudo C")
            except Exception:
                renderer = None
    if renderer is None:
        return _prepend_declaration(_fallback_pseudoc(hlil), declaration)

    root = getattr(hlil, "root", None)
    if root is None:
        return _prepend_declaration(_fallback_pseudoc(hlil), declaration)

    lines = renderer.get_linear_lines(root)
    prefix_lines = (declaration,) if declaration else ()
    rendered = render_linear_lines(lines, func, prefix_lines).rstrip()
    return rendered + "\n" if rendered else ""
