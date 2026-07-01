"""
Language-specific source code processing for multi-language malware generation.

Handles assembly, compilation, and source file management for C, Rust, and Go.
The generation engine produces language-agnostic function chunks; this module
assembles them into a complete source file using language-specific conventions.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# File extension map
LANG_EXTENSIONS: dict[str, str] = {
    "c": ".c",
    "cpp": ".cpp",
    "rust": ".rs",
    "go": ".go",
}

# Compiler tool names for each language (Windows cross-compilation)
LANG_COMPILERS: dict[str, str] = {
    "c": "x86_64-w64-mingw32-gcc",
    "rust": "rustc",
    "go": "go",
}


def source_extension(language: str) -> str:
    return LANG_EXTENSIONS.get(language, ".c")


def source_filename(language: str, output_format: str = "exe") -> str:
    return f"malware_source{source_extension(language)}"


# Output binary extension map
OUTPUT_FORMAT_EXTENSIONS: dict[str, str] = {
    "exe": ".exe",
    "dll": ".dll",
    "shellcode": ".bin",
}


def output_filename(output_format: str = "exe") -> str:
    """Return the output binary filename for the given format."""
    ext = OUTPUT_FORMAT_EXTENSIONS.get(output_format, ".exe")
    return f"malware_source{ext}"


def assemble_source(language: str, plan, chunks: dict[str, str]) -> str:
    """Assemble generated chunks into a complete source file for the given language."""
    if language == "rust":
        return _assemble_rust(plan, chunks)
    elif language == "go":
        return _assemble_go(plan, chunks)
    return _assemble_c(plan, chunks)


def _assemble_c(plan, chunks: dict[str, str]) -> str:
    """Assemble C source — includes, globals, forward decls, function bodies."""
    from .generation_engine import _extract_chunk_signature, _topo_sort

    lines: list[str] = []

    inc_list = list(plan.includes or ["windows.h", "stdio.h"])
    if "winsock2.h" in inc_list and "windows.h" in inc_list:
        inc_list = [i for i in inc_list if i != "winsock2.h"]
        inc_list.insert(inc_list.index("windows.h"), "winsock2.h")
    for inc in inc_list:
        lines.append(f"#include <{inc}>")
    lines.append("")

    if plan.globals_code:
        for raw_gl in plan.globals_code.splitlines():
            stripped = raw_gl.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*"):
                lines.append(raw_gl)
                continue
            if '{' in stripped or '}' in stripped or stripped.startswith("typedef struct"):
                lines.append(raw_gl)
                continue
            parts = [p.strip() for p in raw_gl.split(";") if p.strip()]
            for gl in parts:
                if not gl.endswith(";"):
                    lines.append(gl + ";")
                else:
                    lines.append(gl)
        lines.append("")

    for comp in plan.components:
        chunk = chunks.get(comp.name, "")
        actual_sig = (
            _extract_chunk_signature(chunk)
            if chunk and not chunk.startswith("/*")
            else None
        )
        sig = actual_sig or comp.signature or f"void {comp.name}(void)"
        lines.append(f"{sig};")
    lines.append("")

    for comp in _topo_sort(plan.components):
        code = chunks.get(comp.name, f"/* {comp.name}: not generated */")
        lines.append(code)
        lines.append("")

    return "\n".join(lines)


def _assemble_rust(plan, chunks: dict[str, str]) -> str:
    """Assemble Rust source — extern crate, use imports, statics, function bodies."""
    from .generation_engine import _topo_sort

    lines: list[str] = []

    lines.append("#![allow(unused_imports, dead_code, non_snake_case, non_camel_case_types)]")
    lines.append("")

    for inc in (plan.includes or []):
        if inc.startswith("use ") or inc.startswith("extern "):
            lines.append(f"{inc}")
        else:
            lines.append(f"use {inc};")
    lines.append("")

    if plan.globals_code:
        lines.append(plan.globals_code)
        lines.append("")

    for comp in _topo_sort(plan.components):
        code = chunks.get(comp.name, f"// {comp.name}: not generated")
        lines.append(code)
        lines.append("")

    return "\n".join(lines)


def _assemble_go(plan, chunks: dict[str, str]) -> str:
    """Assemble Go source — package, imports, vars, function bodies."""
    from .generation_engine import _topo_sort

    lines: list[str] = []

    lines.append("package main")
    lines.append("")

    imports = [inc for inc in (plan.includes or []) if inc]
    if imports:
        if len(imports) == 1:
            lines.append(f'import "{imports[0]}"')
        else:
            lines.append("import (")
            for imp in imports:
                if imp.startswith('"'):
                    lines.append(f"\t{imp}")
                else:
                    lines.append(f'\t"{imp}"')
            lines.append(")")
        lines.append("")

    if plan.globals_code:
        lines.append(plan.globals_code)
        lines.append("")

    for comp in _topo_sort(plan.components):
        code = chunks.get(comp.name, f"// {comp.name}: not generated")
        lines.append(code)
        lines.append("")

    return "\n".join(lines)


def fixup_source(language: str, source: str) -> str:
    """Language-specific post-assembly fixups."""
    if language == "c":
        return _fixup_c(source)
    return source


def _fixup_c(source: str) -> str:
    """C-specific: reorder winsock2.h before windows.h if needed."""
    lines = source.split("\n")
    ws2_idx = None
    win_idx = None
    for i, line in enumerate(lines):
        if "#include <winsock2.h>" in line:
            ws2_idx = i
        elif "#include <windows.h>" in line:
            win_idx = i
    if ws2_idx is not None and win_idx is not None and ws2_idx > win_idx:
        ws2_line = lines.pop(ws2_idx)
        lines.insert(win_idx, ws2_line)
    return "\n".join(lines)


def _find_tool(name: str) -> Optional[str]:
    """Find a tool on PATH, with fallback to ~/.cargo/bin for Rust tools."""
    import shutil
    from pathlib import Path as _P
    found = shutil.which(name)
    if found:
        return found
    cargo_bin = _P.home() / ".cargo" / "bin" / name
    if cargo_bin.is_file():
        return str(cargo_bin)
    return None


def compile_check_command(language: str, source_path: str, os_platform: str = "windows") -> Optional[str]:
    """Return a compile-check command (syntax only) for the given language, or None."""
    _is_linux = "linux" in os_platform.lower()
    if language == "c":
        if _is_linux:
            gcc = _find_tool("gcc")
            if gcc:
                return f"{gcc} -fsyntax-only -x c {source_path} 2>&1"
        else:
            mingw = _find_tool("x86_64-w64-mingw32-gcc")
            if mingw:
                return f"{mingw} -fsyntax-only -x c {source_path} 2>&1"
    elif language == "rust":
        rustc = _find_tool("rustc")
        if rustc:
            target = "x86_64-unknown-linux-gnu" if _is_linux else "x86_64-pc-windows-gnu"
            import tempfile as _tf
            _out = _tf.mktemp(suffix=".rlib")
            return f"{rustc} --edition 2021 --target {target} --crate-type lib -A warnings {source_path} -o {_out} 2>&1; _rc=$?; rm -f {_out}; exit $_rc"
    elif language == "go":
        go = _find_tool("go")
        if go:
            goos = "linux" if _is_linux else "windows"
            return f"GOOS={goos} GOARCH=amd64 {go} vet {source_path} 2>&1"
    return None
