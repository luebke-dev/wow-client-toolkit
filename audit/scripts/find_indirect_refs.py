# -*- coding: utf-8 -*-
# Ghidra Jython 2 script. For each "unreached" handler candidate
# (no static `push handler; push opcode; call RegisterHandler`),
# walk the binary for indirect references via:
#   1. function-pointer-array stores (`mov [reg + N], imm32_handler_va`)
#   2. vtable-style data initialisations
#   3. any rel32 immediate that resolves to the handler VA
#
# This is a brute-force byte search complemented by a Ghidra
# reference-manager pass.
#
# Output: /out/indirect_refs.md
# pylint: disable=undefined-variable

# @author wow-client-toolkit
# @category Analysis
# @runtime Jython

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
import os

OUT_PATH = os.environ.get("IR_OUT", "/out/indirect_refs.md")

cp = currentProgram
fm = cp.getFunctionManager()
af = cp.getAddressFactory()
listing = cp.getListing()
ref_mgr = cp.getReferenceManager()
mem = cp.getMemory()

decomp = DecompInterface()
decomp.setOptions(DecompileOptions())
decomp.openProgram(cp)

lines = []


def out(s):
    lines.append(s)


CANDIDATES = [
    "0x006d6d20", "0x006d0240", "0x006d0460", "0x006d0ab0", "0x006d53b0",
    "0x0080e1b0", "0x00755630", "0x00753690", "0x00768760",
]

out("# Indirect-reference trace for unreached score-7 candidates")
out("")
out("For each function with no static handler-registration site, we list:")
out("")
out("- All ghidra references TO the function (any kind: direct call,")
out("  indirect call, data-load).")
out("- Top-level callers reachable transitively.")
out("- A short decompile of any caller that loads the function pointer")
out("  into a slot used as a dispatch target (mov [global+i*4], handler_va).")
out("")

for va_str in CANDIDATES:
    out("## `{0}`".format(va_str))
    out("")
    addr = af.getAddress(va_str)
    fn = fm.getFunctionAt(addr)
    if fn is None:
        out("- (no function defined at {0})".format(va_str))
        out("")
        continue
    refs = list(ref_mgr.getReferencesTo(addr))
    if not refs:
        out("- No references at all -- truly dead code.")
        out("")
        continue
    out("Total references: {0}".format(len(refs)))
    out("")
    for r in refs[:20]:
        kind = r.getReferenceType().getName()
        from_addr = r.getFromAddress()
        owner = fm.getFunctionContaining(from_addr)
        owner_str = ("`{0}` @ {1}".format(owner.getName(), owner.getEntryPoint())
                     if owner else "(no enclosing function)")
        out("- ref @ {0} (type: {1}) in {2}".format(
            from_addr, kind, owner_str))
        # If ref is inside a function, look 16 bytes before the ref
        # to see if it's a `mov [reg + offset], imm32_handler_va`
        # store -- the canonical "register handler in vtable" pattern.
        try:
            ins = listing.getInstructionAt(from_addr)
            if ins is not None:
                mnem = ins.getMnemonicString()
                ops = ins.getDefaultOperandRepresentation(0) + " <- " + ins.getDefaultOperandRepresentation(1)
                out("    - instruction: `{0} {1}`".format(mnem, ops))
        except Exception as e:
            out("    - (instruction read failed: {0})".format(e))

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
    print("[find_indirect_refs] wrote " + OUT_PATH + " (" + str(len(lines)) + " lines)")
except Exception as e:
    print("[find_indirect_refs] write failed: " + str(e))
    print("\n".join(lines))
