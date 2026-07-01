"""
Compiler selector — validates installed compilers and generates build instructions.

Given a target spec with ``installed_compilers``, produces:
  - Cross-compilation flags (e.g., mingw-w64 for Windows from Linux host)
  - Optimisation / stripping guidance
  - Language-specific build commands
"""

from dataclasses import dataclass, field
from typing import List, Optional

from .target_spec import TargetEnvironmentSpec


@dataclass
class CompilerInstruction:
    """A single compiler invocation with all flags."""
    tool: str          # e.g. "x86_64-w64-mingw32-gcc"
    command: str       # full build command
    language: str      # source language ("c", "cpp", etc.)
    target_os: str     # what this produces (e.g. "windows-x86_64")


class CompilerSelector:
    """Validates compilers and generates build instructions for the target."""

    def __init__(self):
        pass  # no external dependencies needed

    def select_build_instructions(
        self,
        source_code: str,
        source_language: str,
        target_spec: TargetEnvironmentSpec,
    ) -> List[CompilerInstruction]:
        """Return concrete build commands for the available compilers.

        Parameters:
            source_code: The generated malware source (used to detect headers/includes)
            source_language: "c", "cpp", etc.
            target_spec: Target environment specification
        """
        instructions = []

        installed = [t.lower() for t in target_spec.installed_compilers]

        if not installed and source_language == "c":
            # Default to gcc if nothing specified
            installed.append("gcc")

        for compiler in installed:
            instr = self._build_instruction(compiler, source_language, target_spec)
            if instr:
                instructions.append(instr)

        return instructions

    def detect_compiler_flags(
        self,
        source_code: str,
        compiler: str,
    ) -> dict[str, str]:
        """Analyse source code for headers/includes and suggest compiler flags."""
        flags = {
            "-O2": "optimisation level 2 (good balance of speed/size)",
            "-s": "strip symbols",
            "-Wall": "all warnings",
        }

        lower_code = source_code.lower()

        # Detect threading requirements
        if "pthread" in lower_code or "#include <thread>" in lower_code:
            if compiler.startswith("gcc") or compiler.startswith("clang"):
                flags["-lpthread"] = "POSIX threads library"
            elif "mingw" in compiler:
                flags["-lstdc++"] = "C++ standard library (MinGW)"

        # Detect Windows API usage
        if "#include <windows.h>" in lower_code or "winapi" in lower_code:
            flags["-lws2_32"] = "Windows Sockets 2"
            flags["-ladvapi32"] = "Advanced WinAPI"

        # Detect crypto library usage
        if "#include <openssl" in lower_code or "crypto.h" in lower_code:
            flags["-lcrypto"] = "OpenSSL crypto"

        return flags


# ---------------------------------------------------------------------------
# Build instruction generators per compiler
# ---------------------------------------------------------------------------

    def _build_instruction(
        self,
        compiler: str,
        language: str,
        spec: TargetEnvironmentSpec,
    ) -> Optional[CompilerInstruction]:
        """Build a single CompilerInstruction for the given compiler."""
        arch = "x86_64"  # default

        if compiler.startswith("gcc"):
            target_os = self._infer_target(spec)
            cmd = f"{compiler} -O2 -s -Wall source.c -o malware{'.exe' if 'windows' in target_os else ''}"
            return CompilerInstruction(
                tool=compiler, command=cmd, language=language, target_os=target_os
            )

        elif compiler.startswith("clang"):
            target_os = self._infer_target(spec)
            cmd = f"{compiler} -O2 -s source.c -o malware{'.exe' if 'windows' in target_os else ''}"
            return CompilerInstruction(
                tool=compiler, command=cmd, language=language, target_os=target_os
            )

        elif "mingw" in compiler:
            cmd = f"{compiler} -O2 -s source.c -o malware.exe -lws2_32 -ladvapi32"
            return CompilerInstruction(
                tool=compiler, command=cmd, language="c", target_os="windows-x86_64"
            )

        elif compiler == "rustc":
            target_os = self._infer_target(spec)
            if "windows" in target_os:
                cmd = "rustc --target x86_64-pc-windows-gnu -C opt-level=2 -C strip=symbols malware_source.rs -o malware_source.exe"
            else:
                cmd = "rustc -C opt-level=2 -C strip=symbols malware_source.rs -o malware_source"
            return CompilerInstruction(tool="rustc", command=cmd, language="rust", target_os=target_os)

        elif compiler == "go":
            target_os = self._infer_target(spec)
            if "windows" in target_os:
                cmd = "GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags='-s -w' -o malware_source.exe malware_source.go"
            else:
                cmd = "CGO_ENABLED=0 go build -ldflags='-s -w' -o malware_source malware_source.go"
            return CompilerInstruction(tool="go", command=cmd, language="go", target_os=target_os)

        # Unknown compiler — generic fallback
        if spec.os_platform.value == "windows":
            ext = ".exe"
        else:
            ext = ""
        cmd = f"{compiler} source.{language[:1]} -o malware{ext}"
        return CompilerInstruction(tool=compiler, command=cmd, language=language, target_os=self._infer_target(spec))

    @staticmethod
    def _infer_target(spec: TargetEnvironmentSpec) -> str:
        """Infer the target OS string from spec."""
        if "windows" in spec.os_version.lower():
            return "windows-x86_64"
        return f"{spec.os_platform.value}-x86_64"
