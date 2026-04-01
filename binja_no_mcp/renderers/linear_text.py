from __future__ import annotations


def line_to_text(line: object) -> str:
    tokens = getattr(line, "tokens", None)
    if not tokens:
        return str(line)
    return "".join(getattr(token, "text", str(token)) for token in tokens)


def _line_address(line: object) -> int | None:
    for attribute in ("address", "addr"):
        value = getattr(line, attribute, None)
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                return None
    return None


def _line_indent(text: str) -> str:
    return text[: len(text) - len(text.lstrip(" \t"))]


def _comment_text(comment: object) -> str | None:
    if comment is None:
        return None
    text = str(comment).replace("\r\n", "\n").replace("\r", "\n").strip("\n")
    return text or None


def _get_comment_at(target: object, address: int) -> str | None:
    getter = getattr(target, "get_comment_at", None)
    if not callable(getter):
        return None
    try:
        return _comment_text(getter(address))
    except Exception:
        return None


def _comment_lines_for_address(func: object | None, address: int) -> list[str]:
    comments: list[str] = []
    seen: set[str] = set()

    for target in (func, getattr(func, "view", None)):
        comment = _get_comment_at(target, address)
        if not comment or comment in seen:
            continue
        seen.add(comment)
        comments.extend(comment.splitlines())

    return comments


def render_linear_lines(lines: object, func: object | None = None) -> str:
    rendered_lines: list[str] = []
    emitted_comment_addresses: set[int] = set()

    for line in lines:
        text = line_to_text(line)
        address = _line_address(line)
        if address is not None and address not in emitted_comment_addresses:
            comment_lines = _comment_lines_for_address(func, address)
            if comment_lines:
                indent = _line_indent(text)
                rendered_lines.extend(f"{indent}// {comment_line}" for comment_line in comment_lines)
            emitted_comment_addresses.add(address)
        rendered_lines.append(text)

    rendered = "\n".join(rendered_lines).rstrip()
    return f"{rendered}\n" if rendered else ""
