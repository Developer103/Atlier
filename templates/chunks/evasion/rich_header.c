// chunk: evasion/rich_header
// depends: (none)
// provides: (post-compile transform — not a runtime chunk)
// risk: none
// note: Injects a fake Rich header into MinGW PE binaries to mimic MSVC-compiled executables.
//       CrowdStrike and other ML models use Rich header presence/absence as a classification signal.
//       MinGW binaries lack Rich headers entirely, which flags them as "unknown compiler = suspicious".
//       This is a POST-COMPILE transform applied by the assembler, not runtime code.
//
// The Rich header is a PE structure between the DOS stub and PE signature that records
// which MSVC tools and versions were used to build the binary. Its presence signals
// "compiled by legitimate Visual Studio toolchain" to ML classifiers.
//
// This file is a reference — the actual injection is done by inject_rich_header() in assembler.py.
// Format: XOR-encrypted tool entries with a "Rich" signature and checksum.

// No runtime code — this is a build-time transform.
// See assembler.py:inject_rich_header() for the implementation.
