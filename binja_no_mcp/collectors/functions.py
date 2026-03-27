from __future__ import annotations

from ..models import FunctionMeta
from ..naming import sanitize_name


def freeze_recognized_functions(bv: object) -> list[object]:
    return sorted(list(getattr(bv, "functions", [])), key=lambda func: getattr(func, "start", 0))


def _safe_symbol_name(symbol: object | None) -> str | None:
    if symbol is None:
        return None
    for attribute in ("short_name", "full_name", "raw_name", "name"):
        value = getattr(symbol, attribute, None)
        if value:
            return str(value)
    return None


def _raw_name(func: object) -> str:
    symbol = getattr(func, "symbol", None)
    raw_name = getattr(symbol, "raw_name", None)
    if raw_name:
        return str(raw_name)
    name = getattr(func, "name", None)
    if name:
        return str(name)
    return f"sub_{getattr(func, 'start', 0):x}"


def function_identity(func: object) -> tuple[str, str, str]:
    raw_name = _raw_name(func)
    name = str(getattr(func, "name", None) or raw_name)
    return name, raw_name, sanitize_name(raw_name)


def _token_text(token: object) -> str:
    return str(getattr(token, "text", token))


def _type_line_text(line: object) -> str:
    tokens = getattr(line, "tokens", None)
    if tokens is None:
        return str(line)
    return "".join(_token_text(token) for token in tokens)


def _collapse_ws(text: str) -> str:
    return " ".join(text.split())


def function_declaration(func: object) -> str | None:
    get_type_tokens = getattr(func, "get_type_tokens", None)
    if callable(get_type_tokens):
        lines = [_type_line_text(line).strip() for line in get_type_tokens()]
        lines = [line for line in lines if line]
        if lines:
            return _collapse_ws(" ".join(lines))

    type_tokens = getattr(func, "type_tokens", None)
    if type_tokens:
        text = "".join(_token_text(token) for token in type_tokens).strip()
        if text:
            return _collapse_ws(text)

    func_type = getattr(func, "type", None)
    if func_type is None:
        return None
    text = str(func_type).strip()
    return _collapse_ws(text) if text else None


def _normalize_bool(value: object) -> bool | None:
    if value is None:
        return None
    if hasattr(value, "value"):
        return bool(getattr(value, "value"))
    if isinstance(value, bool):
        return value
    return bool(value)


def _unique_function_addresses(funcs: object) -> list[int]:
    addresses = {int(getattr(func, "start")) for func in funcs if getattr(func, "start", None) is not None}
    return sorted(addresses)


def _unique_addresses(addresses: object) -> list[int]:
    return sorted({int(address) for address in addresses})


def _enum_name(value: object) -> str | None:
    if value is None:
        return None
    return str(getattr(value, "name", value))


def _prototype_location(location: object | None) -> dict[str, object] | None:
    if location is None:
        return None
    return {
        "source_type": _enum_name(getattr(location, "source_type", None) or getattr(location, "type", None)),
        "index": getattr(location, "index", None),
        "storage": getattr(location, "storage", None),
        "name": getattr(location, "name", None),
    }


def _prototype_for_function(func: object) -> tuple[str | None, dict[str, object]]:
    declaration = function_declaration(func)
    func_type = getattr(func, "type", None)
    if func_type is None:
        return declaration, {
            "return_type": None,
            "parameters": [],
            "parameter_count": 0,
            "has_variable_arguments": None,
        }

    parameters: list[dict[str, object]] = []
    for index, parameter in enumerate(getattr(func_type, "parameters", []) or []):
        raw_name = str(getattr(parameter, "name", "") or "")
        parameters.append(
            {
                "index": index,
                "name": raw_name or f"arg_{index}",
                "raw_name": raw_name,
                "type": str(getattr(parameter, "type", None)) if getattr(parameter, "type", None) is not None else None,
                "location": _prototype_location(getattr(parameter, "location", None)),
            }
        )

    return_type = getattr(func_type, "return_value", None)
    variable_arguments = getattr(func_type, "has_variable_arguments", None)
    if variable_arguments is None:
        variable_arguments = getattr(func, "has_variable_arguments", None)
    return declaration, {
        "return_type": str(return_type) if return_type is not None else None,
        "parameters": parameters,
        "parameter_count": len(parameters),
        "has_variable_arguments": _normalize_bool(variable_arguments),
    }


def build_function_meta(
    func: object,
    hlil_file: str | None,
    pseudoc_file: str | None,
    mlil_file: str | None,
    mlil_ssa_file: str | None,
    llil_file: str | None,
    export_error: str | None = None,
) -> FunctionMeta:
    name, raw_name, sanitized_name = function_identity(func)
    declaration, prototype = _prototype_for_function(func)
    callers = _unique_function_addresses(getattr(func, "callers", []))
    callees = _unique_addresses(getattr(func, "callee_addresses", []))
    calling_convention = getattr(func, "calling_convention", None)
    calling_convention_name = getattr(calling_convention, "name", None)

    return FunctionMeta(
        start=int(getattr(func, "start")),
        name=name,
        raw_name=raw_name,
        sanitized_name=sanitized_name,
        declaration=declaration,
        prototype=prototype,
        symbol_name=_safe_symbol_name(getattr(func, "symbol", None)),
        calling_convention=str(calling_convention_name) if calling_convention_name else None,
        can_return=_normalize_bool(getattr(func, "can_return", None)),
        hlil_available=hlil_file is not None,
        hlil_file=hlil_file,
        pseudoc_file=pseudoc_file,
        mlil_file=mlil_file,
        mlil_ssa_file=mlil_ssa_file,
        llil_file=llil_file,
        caller_count=len(callers),
        callee_count=len(callees),
        callers=callers,
        callees=callees,
        export_error=export_error,
    )
