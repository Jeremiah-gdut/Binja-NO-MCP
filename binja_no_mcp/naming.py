from __future__ import annotations

import hashlib
import re


_SANITIZE_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")
_COLLAPSE_PATTERN = re.compile(r"_+")


def sanitize_name(name: str, max_len: int = 80) -> str:
    sanitized = _SANITIZE_PATTERN.sub("_", name)
    sanitized = _COLLAPSE_PATTERN.sub("_", sanitized).strip("_")
    if not sanitized:
        sanitized = "unnamed"
    if len(sanitized) > max_len:
        suffix = hashlib.sha1(name.encode("utf-8")).hexdigest()[:8]
        sanitized = f"{sanitized[:max_len]}_{suffix}"
    return sanitized


def function_id(start: int) -> str:
    return f"0x{start:x}"


def function_file_stem(start: int) -> str:
    return function_id(start)


def hex_addr(value: int | None) -> str | None:
    if value is None:
        return None
    return f"0x{value:016x}"
