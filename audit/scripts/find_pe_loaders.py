# -*- coding: utf-8 -*-
# Ghidra Jython 2 script. Hunts for sister functions to
# FUN_00872350 (the writeup-named manual PE loader).
#
# Strategy: any code path that walks a server-supplied buffer as a
# PE will need to check the MZ magic at offset 0. Find every place
# that does `cmp ... 0x5A4D` or compares a dword for the MZ-PE
# combination, then classify each owning function.
#
# Output: /out/pe_loaders.md
# pylint: disable=undefined-variable

# @author wow-client-toolkit
# @category Analysis
# @runtime Jython

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
import os

OUT_PATH = os.environ.get("PE_OUT", "/out/pe_loaders.md")

cp = currentProgram
fm = cp.getFunctionManager()
af = cp.getAddressFactory()
listing = cp.getListing()
mem = cp.getMemory()

decomp = DecompInterface()
decomp.setOptions(DecompileOptions())
decomp.openProgram(cp)

lines = []


def out(s):
    lines.append(s)


out("# PE-loader candidates in Wow.exe")
out("")
out("Identifies every code path that checks for the `MZ` magic")
out("at offset 0 of a buffer -- candidate sister functions to")
out("`FUN_00872350` (the documented manual PE loader closed by")
out("Patch 2). If any sister loader exists and is not patched, an")
out("attacker can route around Patch 2.")
out("")

# Search patterns:
# 1. `66 81 78 00 4D 5A`   = cmp word ptr [eax], 0x5A4D  ("MZ")
# 2. `66 81 7E 00 4D 5A`   = cmp word ptr [esi], 0x5A4D
# 3. `66 83 78 00 5A`      = cmp word ptr [eax], 0x5A   (less specific)
# 4. `66 81 39 4D 5A`      = cmp word ptr [ecx], 0x5A4D
# 5. `81 ?? 00 4D 5A 00 00` = cmp dword [reg+0], "MZ\0\0"
PATTERNS = [
    ("cmp word [eax], 'MZ'", bytearray([0x66, 0x81, 0x78, 0x00, 0x4D, 0x5A])),
    ("cmp word [esi], 'MZ'", bytearray([0x66, 0x81, 0x7E, 0x00, 0x4D, 0x5A])),
    ("cmp word [ecx], 'MZ'", bytearray([0x66, 0x81, 0x39, 0x4D, 0x5A, 0x00])),
    ("cmp word [edi], 'MZ'", bytearray([0x66, 0x81, 0x3F, 0x4D, 0x5A, 0x00])),
    ("cmp word [edx], 'MZ'", bytearray([0x66, 0x81, 0x3A, 0x4D, 0x5A, 0x00])),
    ("cmp word [ebx], 'MZ'", bytearray([0x66, 0x81, 0x3B, 0x4D, 0x5A, 0x00])),
    ("cmp word [ebp], 'MZ'", bytearray([0x66, 0x81, 0x7D, 0x00, 0x4D, 0x5A])),
]

# Also look for the literal "MZ\x00\x00" sequence used as a
# 32-bit immediate in compares. Less common but covers
# alternative compiler output.
WIDE_PATTERNS = [
    ("dword imm 0x00005A4D", bytearray([0x4D, 0x5A, 0x00, 0x00])),
]

hit_funcs = {}

for label, needle in PATTERNS:
    addr = mem.findBytes(cp.getMinAddress(), bytes(needle), None, True, monitor)
    while addr is not None:
        f = fm.getFunctionContaining(addr)
        if f is not None:
            key = str(f.getEntryPoint())
            if key not in hit_funcs:
                hit_funcs[key] = (f, [])
            hit_funcs[key][1].append((label, str(addr)))
        addr = mem.findBytes(addr.add(1), bytes(needle), None, True, monitor)

# Suppress matches in functions that look like generic file-loading
# code (PE format support is needed by addon DLLs, install hooks,
# etc. -- not all loaders are RCE primitives). We tag each function
# with whether it ALSO calls VirtualAlloc + manually walks section
# headers (the load-then-execute pattern).

def has_signature_of_executor(fn):
    """Heuristic: function calls VirtualAlloc/Protect AND VirtualProtect
    AND walks a section-header-like loop (`add edi, 0x28` = section
    header size). Indicates "load then make executable" = bad."""
    body = fn.getBody()
    has_valloc = False
    has_vprotect = False
    has_section_walk = False
    it = listing.getInstructions(body, True)
    while it.hasNext():
        ins = it.next()
        for ref in ins.getReferencesFrom():
            tgt = ref.getToAddress()
            if tgt is None:
                continue
            sym = cp.getSymbolTable().getPrimarySymbol(tgt)
            if sym is None:
                continue
            n = sym.getName()
            if n == "VirtualAlloc":
                has_valloc = True
            if n == "VirtualProtect":
                has_vprotect = True
        # Section-header-walk heuristic: "add reg, 0x28"
        if ins.getMnemonicString().lower() == "add":
            ops = ins.getDefaultOperandRepresentation(1)
            if "0x28" in ops or "40" == ops:
                has_section_walk = True
    return has_valloc, has_vprotect, has_section_walk


out("Found {0} unique functions containing an MZ-magic check.".format(len(hit_funcs)))
out("")

# Sort by danger: loader-shaped first.
ranked = []
for key, (fn, hits) in hit_funcs.items():
    valloc, vprotect, swalk = has_signature_of_executor(fn)
    score = 0
    if valloc:
        score += 2
    if vprotect:
        score += 3
    if swalk:
        score += 2
    ranked.append((score, fn, hits, valloc, vprotect, swalk))
ranked.sort(key=lambda r: -r[0])

out("## Functions sorted by loader-shape score")
out("")
out("Score = +2 calls VirtualAlloc, +3 calls VirtualProtect, +2 walks")
out("sections (`add reg, 0x28`). >= 5 = full load-then-execute = RCE")
out("primitive. >= 2 = partial PE walk (could just be header-checking).")
out("0 = MZ check exists in code (e.g. an addon validator) but no")
out("dangerous follow-through.")
out("")

for score, fn, hits, valloc, vprotect, swalk in ranked[:30]:
    marker = ("RCE-LOADER" if score >= 5 else
              "PARTIAL" if score >= 2 else "info")
    out("- score=**{0}** [{1}] `{2}` @ {3}".format(
        score, marker, fn.getName(), fn.getEntryPoint()))
    out("    - VirtualAlloc={0} VirtualProtect={1} SectionWalk={2}".format(
        valloc, vprotect, swalk))
    for label, addr in hits[:3]:
        out("    - `{0}` @ {1}".format(label, addr))
out("")

# Decompile every score>=5 site (the new loader candidates).
out("## Top loader candidates decompiled")
out("")
shown = 0
for score, fn, _, _, _, _ in ranked:
    if score < 5:
        break
    if shown >= 5:
        break
    out("### `{0}` @ {1} -- score {2}".format(
        fn.getName(), fn.getEntryPoint(), score))
    out("")
    out("```c")
    res = decomp.decompileFunction(fn, 60, ConsoleTaskMonitor())
    if res.decompileCompleted():
        c = res.getDecompiledFunction().getC()
        # Show only the first 100 lines so the report stays scanable.
        for ln in c.splitlines()[:100]:
            out(ln)
    out("```")
    out("")
    shown += 1

if shown == 0:
    out("(no loader-shaped functions found beyond the known FUN_00872350)")
    out("")

# Write
out_dir = os.path.dirname(OUT_PATH)
if out_dir and not os.path.isdir(out_dir):
    try:
        os.makedirs(out_dir)
    except Exception:
        pass
try:
    f = open(OUT_PATH, "w")
    f.write("\n".join(lines))
    f.close()
    print("[find_pe_loaders] wrote " + OUT_PATH + " (" + str(len(lines)) + " lines)")
except Exception as e:
    print("[find_pe_loaders] write failed: " + str(e))
    print("\n".join(lines))
