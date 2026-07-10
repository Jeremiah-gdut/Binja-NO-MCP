from __future__ import annotations


ADDRESS_COLUMN_WIDTH = 18


def line_to_text(line: object) -> str:
    tokens = getattr(line, "tokens", None)
    if not tokens:
        return str(line)
    return "".join(getattr(token, "text", str(token)) for token in tokens)


def _line_address(line: object) -> int | None:
    if getattr(line, "il_instruction", None) is None:
        return None
    for attribute in ("address", "addr"):
        value = getattr(line, attribute, None)
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                return None
    return None


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


def format_linear_line(text: str, address: int | None = None) -> str:
    if not text:
        return " " * ADDRESS_COLUMN_WIDTH
    column = f"0x{address:x}" if address is not None else ""
    return f"{column:<{ADDRESS_COLUMN_WIDTH}} {text}"


def format_unaddressed_text(text: str) -> str:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").splitlines()
    return "\n".join(format_linear_line(line) for line in lines).rstrip() + "\n" if lines else ""


def _physical_lines(text: str, address: int | None) -> list[tuple[str, int | None]]:
    return [
        (part, address if part else None)
        for part in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    ]


def render_linear_lines(
    lines: object,
    func: object | None = None,
    prefix_lines: tuple[str, ...] = (),
) -> str:
    rendered_lines = [format_linear_line(line) for line in prefix_lines]
    emitted_comment_addresses: set[int] = set()

    for line in lines:
        text = line_to_text(line)
        address = _line_address(line)
        if address is not None and address not in emitted_comment_addresses:
            rendered_lines.extend(format_linear_line(f"// {comment}", address) for comment in _comment_lines_for_address(func, address))
            emitted_comment_addresses.add(address)
        rendered_lines.extend(format_linear_line(part, part_address) for part, part_address in _physical_lines(text, address))

    rendered = "\n".join(rendered_lines).rstrip()
    return f"{rendered}\n" if rendered else ""
