"""Utilities for computing deterministic signatures from normalized rows."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Tuple

_CONTROL_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "case",
    "return",
    "sizeof",
    "using",
    "lock",
    "else",
    "try",
    "await",
}

_RETURN_MODIFIERS = {
    "public",
    "private",
    "protected",
    "static",
    "inline",
    "virtual",
    "extern",
    "constexpr",
    "friend",
    "mutable",
    "register",
    "volatile",
    "override",
    "final",
    "abstract",
    "synchronized",
    "async",
    "explicit",
    "sealed",
    "native",
}

_LANGUAGE_ALIASES = {
    "c++": "cpp",
    "c#": "csharp",
    "objective-c++": "objective-cpp",
    "objc": "objective-c",
    "objc++": "objective-cpp",
    "typescriptreact": "typescript",
    "javascriptreact": "javascript",
}

_TRAILING_RETURN_RE = re.compile(r"->\s*(?P<return>[^{};]+)")


@dataclass
class SignatureParts:
    name: str
    params: str
    return_type: str = ""


def _normalize_line_endings(text: str) -> str:
    """Convert Windows or old Mac newlines to ``\\n``."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _escape_literal(text: str) -> str:
    normalized = _normalize_line_endings(text)
    escaped = normalized.replace("\\", "\\\\").replace("\t", "\\t")
    return escaped.replace("\n", "\\n")


def canonicalize_code(text: str) -> str:
    """Produce a stable representation of a code snippet for hashing."""
    normalized = _normalize_line_endings(text)
    lines = (line.rstrip() for line in normalized.split("\n"))
    canonical = "\n".join(lines).strip()
    return _escape_literal(canonical)


def _normalize_whitespace(value: str) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", " ", value.strip())


def _normalize_parameter_list(value: str) -> str:
    if not value:
        return ""
    compact = _normalize_whitespace(value)
    return re.sub(r"\s*,\s*", ", ", compact)


def _normalize_return_type(value: str) -> str:
    return _normalize_whitespace(value)


def _split_pointer_name(token: str) -> Tuple[str, str]:
    idx = 0
    length = len(token)
    while idx < length and token[idx] in "*&":
        idx += 1
    name = token[idx:]
    pointer = token[:idx]
    return (name or token, pointer)


def _strip_return_modifiers(tokens: Iterable[str]) -> Tuple[str, ...]:
    result: list[str] = list(tokens)
    while result and result[0].lower() in _RETURN_MODIFIERS:
        result.pop(0)
    return tuple(result)


def _prepare_candidate(candidate: str) -> str:
    text = candidate.strip()
    while text and text[-1] in "{;":
        text = text[:-1].rstrip()
    return text


def _split_candidate(candidate: str) -> Optional[Tuple[str, str, str]]:
    text = _prepare_candidate(candidate)
    if "(" not in text:
        return None
    start = text.find("(")
    depth = 0
    end = None
    for index, char in enumerate(text[start:], start=start):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                end = index
                break
    if end is None:
        return None
    prefix = text[:start]
    params = text[start + 1 : end]
    suffix = text[end + 1 :]
    return prefix.strip(), params.strip(), suffix.strip()


def _trailing_return_type(suffix: str) -> str:
    if not suffix:
        return ""
    match = _TRAILING_RETURN_RE.search(suffix)
    if not match:
        return ""
    return _normalize_return_type(match.group("return"))


_C_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_C_LINE_COMMENT_RE = re.compile(r"//.*?$", re.MULTILINE)


def _strip_c_comments(code: str) -> str:
    without_block = _C_BLOCK_COMMENT_RE.sub(" ", code)
    return _C_LINE_COMMENT_RE.sub("", without_block)


def _split_prefix(prefix: str) -> Tuple[str, str]:
    text = prefix.strip()
    if not text:
        return "", ""
    tokens = re.split(r"\s+", text)
    if not tokens:
        return "", ""
    name_token = tokens[-1]
    name, pointer_prefix = _split_pointer_name(name_token)
    return_tokens = list(tokens[:-1])
    if pointer_prefix:
        return_tokens.append(pointer_prefix)
    cleaned_tokens = _strip_return_modifiers(return_tokens)
    return_type = _normalize_return_type(" ".join(cleaned_tokens))
    return name, return_type


def _extract_c_like_signature(code: str) -> Optional[SignatureParts]:
    sanitized = _strip_c_comments(code)
    sanitized = _normalize_line_endings(sanitized)
    candidate = ""
    depth = 0

    for raw_line in sanitized.split("\n"):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        candidate = f"{candidate} {line}".strip() if candidate else line
        depth += line.count("(") - line.count(")")
        if depth > 0:
            continue

        if "(" not in candidate or ")" not in candidate:
            if "(" not in candidate:
                candidate = ""
            continue

        parsed = _split_candidate(candidate)
        if not parsed:
            candidate = ""
            continue
        prefix, params, suffix = parsed
        name, return_type = _split_prefix(prefix)
        if not name or name.lower() in _CONTROL_KEYWORDS:
            candidate = ""
            continue
        trailing = _trailing_return_type(suffix)
        if trailing:
            return_type = trailing
        params_clean = _normalize_parameter_list(params)
        return SignatureParts(
            name=name,
            params=params_clean,
            return_type=_normalize_return_type(return_type),
        )

    return None


_PY_PATTERN = re.compile(
    r"^\s*def\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[\s\S]*?)\)\s*(?:->\s*(?P<return>[^:\n]+))?\s*:",
    re.MULTILINE,
)


def _extract_python_signature(code: str) -> Optional[SignatureParts]:
    match = _PY_PATTERN.search(code)
    if not match:
        return None
    params = _normalize_parameter_list(match.group("params") or "")
    return_type = _normalize_return_type(match.group("return") or "")
    return SignatureParts(name=match.group("name"), params=params, return_type=return_type)


_RUBY_PATTERN = re.compile(
    r"^\s*def\s+(?P<name>[A-Za-z_]\w*[!?=]?)\s*(?:\((?P<params>[^\)]*)\))?",
    re.MULTILINE,
)


def _extract_ruby_signature(code: str) -> Optional[SignatureParts]:
    match = _RUBY_PATTERN.search(code)
    if not match:
        return None
    params = _normalize_parameter_list(match.group("params") or "")
    return SignatureParts(name=match.group("name"), params=params, return_type="")


_GO_PATTERN = re.compile(
    r"^\s*func\s+(?P<receiver>\([^\)]*\)\s+)?(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[\s\S]*?)\)\s*(?P<return>(?:\([\s\S]*?\))|(?:[^\s\{][^\s\{]*))?",
    re.MULTILINE,
)


def _extract_go_signature(code: str) -> Optional[SignatureParts]:
    match = _GO_PATTERN.search(code)
    if not match:
        return None
    receiver = match.group("receiver") or ""
    name = match.group("name")
    if receiver:
        receiver_body = receiver.strip()[1:-1] if receiver.strip().startswith("(") and receiver.strip().endswith(")") else receiver
        receiver_tokens = receiver_body.strip().split()
        if receiver_tokens:
            receiver_type = receiver_tokens[-1].lstrip("*&")
            if receiver_type:
                name = f"{receiver_type}.{name}"
    params = _normalize_parameter_list(match.group("params") or "")
    return_type = _normalize_return_type(match.group("return") or "")
    return SignatureParts(name=name, params=params, return_type=return_type)


_RUST_PATTERN = re.compile(
    r"^\s*fn\s+(?P<name>[A-Za-z_]\w*)\s*(?:<[^>]*>\s*)?\((?P<params>[\s\S]*?)\)\s*(?:->\s*(?P<return>[^{;]+))?",
    re.MULTILINE,
)


def _extract_rust_signature(code: str) -> Optional[SignatureParts]:
    match = _RUST_PATTERN.search(code)
    if not match:
        return None
    params = _normalize_parameter_list(match.group("params") or "")
    return_type = match.group("return") or ""
    if "where" in return_type:
        return_type = return_type.split("where", 1)[0]
    return SignatureParts(
        name=match.group("name"),
        params=params,
        return_type=_normalize_return_type(return_type),
    )


_PHP_PATTERN = re.compile(
    r"^\s*(?:(?:public|private|protected|static|abstract|final)\s+)*function\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[\s\S]*?)\)\s*(?::\s*(?P<return>[^{;]+))?",
    re.IGNORECASE | re.MULTILINE,
)


def _extract_php_signature(code: str) -> Optional[SignatureParts]:
    match = _PHP_PATTERN.search(code)
    if not match:
        return None
    params = _normalize_parameter_list(match.group("params") or "")
    return_type = _normalize_return_type(match.group("return") or "")
    return SignatureParts(name=match.group("name"), params=params, return_type=return_type)


_JS_FUNCTION_PATTERN = re.compile(
    r"^\s*(?:async\s+)?function(?:\s+\*)?\s+(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[\s\S]*?)\)\s*(?::\s*(?P<return>[^{=;\{]+))?",
    re.MULTILINE,
)
_JS_METHOD_PATTERN = re.compile(
    r"^\s*(?:async\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[\s\S]*?)\)\s*(?::\s*(?P<return>[^{=;\{]+))?\s*\{",
    re.MULTILINE,
)


def _extract_js_signature(code: str) -> Optional[SignatureParts]:
    match = _JS_FUNCTION_PATTERN.search(code)
    if match and match.group("name").lower() not in _CONTROL_KEYWORDS:
        params = _normalize_parameter_list(match.group("params") or "")
        return_type = _normalize_return_type(match.group("return") or "")
        return SignatureParts(
            name=match.group("name"),
            params=params,
            return_type=return_type,
        )
    match = _JS_METHOD_PATTERN.search(code)
    if match and match.group("name").lower() not in _CONTROL_KEYWORDS:
        params = _normalize_parameter_list(match.group("params") or "")
        return_type = _normalize_return_type(match.group("return") or "")
        return SignatureParts(
            name=match.group("name"),
            params=params,
            return_type=return_type,
        )
    return None


def _extract_generic_signature(code: str) -> Optional[SignatureParts]:
    normalized = _normalize_line_endings(code)
    for line in normalized.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(("//", "#", "/*", "*", "--")):
            continue
        return SignatureParts(name=stripped, params="", return_type="")
    return None


_LANGUAGE_EXTRACTORS = {
    "python": (_extract_python_signature,),
    "ruby": (_extract_ruby_signature,),
    "go": (_extract_go_signature,),
    "rust": (_extract_rust_signature,),
    "php": (_extract_php_signature,),
    "javascript": (_extract_js_signature,),
    "typescript": (_extract_js_signature,),
    "c": (_extract_c_like_signature,),
    "cpp": (_extract_c_like_signature,),
    "csharp": (_extract_c_like_signature,),
    "java": (_extract_c_like_signature,),
    "objective-c": (_extract_c_like_signature,),
    "objective-cpp": (_extract_c_like_signature,),
    "swift": (_extract_c_like_signature,),
    "scala": (_extract_c_like_signature,),
    "kotlin": (_extract_c_like_signature,),
    "perl": (_extract_c_like_signature,),
    "vb": (_extract_c_like_signature,),
}

_FALLBACK_EXTRACTORS = (_extract_c_like_signature, _extract_generic_signature)


def _normalize_language(language: str) -> str:
    if not language:
        return ""
    token = language.strip().lower()
    return _LANGUAGE_ALIASES.get(token, token)


def _format_signature(parts: SignatureParts) -> str:
    name = parts.name.strip()
    if not name:
        return ""
    params = _normalize_parameter_list(parts.params)
    return_type = _normalize_return_type(parts.return_type)
    signature = f"{name}({params})" if params else f"{name}()"
    if return_type:
        signature = f"{signature} -> {return_type}"
    return _escape_literal(signature)


def extract_function_signature(code: str, language: str) -> str:
    if not code:
        return ""
    normalized_language = _normalize_language(language)
    extractors: Tuple = _LANGUAGE_EXTRACTORS.get(normalized_language, ())
    for extractor in (*extractors, *_FALLBACK_EXTRACTORS):
        parts = extractor(code)
        if parts and parts.name:
            formatted = _format_signature(parts)
            if formatted:
                return formatted
    return ""


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_signature(
    *,
    language: str,
    cwe: str,
    code_before: str,
    code_after: str,
) -> Tuple[str, str, str]:
    """Return ``(signature, before_hash, after_hash)`` for a normalized row."""
    canonical_before = canonicalize_code(code_before) if code_before else ""
    canonical_after = canonicalize_code(code_after) if code_after else ""

    before_hash = _hash_text(canonical_before) if canonical_before else ""
    after_hash = _hash_text(canonical_after) if canonical_after else ""

    signature_text = extract_function_signature(code_after or code_before, language)
    return signature_text, before_hash, after_hash


def compute_row_signature(row: Dict[str, str]) -> Dict[str, str]:
    """Compute signature fields for a CSV row compatible with ``common.SCHEMA``."""
    language = (row.get("language") or "").strip()
    cwe = (row.get("cwe") or "").strip()
    signature, before_hash, after_hash = build_signature(
        language=language,
        cwe=cwe,
        code_before=row.get("code_before") or "",
        code_after=row.get("code_after") or "",
    )
    return {
        "signature": signature,
        "code_before_hash": before_hash,
        "code_after_hash": after_hash,
        "language": language,
        "cwe": cwe,
    }


__all__ = [
    "canonicalize_code",
    "extract_function_signature",
    "build_signature",
    "compute_row_signature",
]
