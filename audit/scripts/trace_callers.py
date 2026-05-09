# -*- coding: utf-8 -*-
# Ghidra Jython 2 script. For each "unreached" candidate handler
# (functions flagged by find_write_primitives.py at score >= 5
# but with no static handler-registration site), walk the
# call-graph BACKWARDS until either:
#
#   1. A packet handler is hit (the function is registered as
#      a network message handler via the standard pattern -- in
#      which case the candidate IS reachable via that handler's
#      internal logic and needs further inspection), or
#   2. Depth limit reached (probably init / asset-load context,
#      not packet-reachable from a worker thread).
#
# A packet handler is identified at runtime by its address being
# pushed as the handler arg in a `push handler; push opcode; call
# RegisterHandler` 3-instruction pattern. We approximate by
# scanning the binary for the function's literal address bytes
# preceded by a 0x68 push opcode.
#
# Output: /out/caller_traces.md
# pylint: disable=undefined-variable

# @author wow-client-toolkit
# @category Analysis
# @runtime Jython

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
import os

OUT_PATH = os.environ.get("TC_OUT", "/out/caller_traces.md")
MAX_DEPTH = 6

cp = currentProgram
fm = cp.getFunctionManager()
af = cp.getAddressFactory()
ref_mgr = cp.getReferenceManager()
mem = cp.getMemory()

decomp = DecompInterface()
decomp.setOptions(DecompileOptions())
decomp.openProgram(cp)

lines = []


def out(s):
    lines.append(s)


# Score-7 + score-4 unreached candidates (no static handler-
# registration). Discovered by find_write_primitives.py + the
# bulk handler-classification.
CANDIDATES = [
    # Score-7 unreached
    "0x006d6d20", "0x006d0240", "0x006d0460", "0x006d0ab0",
    "0x006d53b0", "0x0080e1b0", "0x00755630",
    # Score-4 unreached (those without a single-opcode hit)
    "0x004d7100", "0x004e5a50", "0x00503990", "0x0050be70",
    "0x005c29c0", "0x005f79a0", "0x006b8720", "0x006cdf30",
    "0x0073c8e0",
]


def is_handler_registered(addr):
    """Check binary for `push imm32; push imm32; call RegisterHandler`
    pattern with imm32 = addr's VA in the first push. Returns the
    opcode if matched, else None."""
    va = addr.getOffset()
    needle = bytearray([va & 0xFF, (va >> 8) & 0xFF,
                        (va >> 16) & 0xFF, (va >> 24) & 0xFF])
    cur = mem.findBytes(cp.getMinAddress(), bytes(needle), None, True, monitor)
    while cur is not None:
        # check prev byte = 0x68 (push imm32)
        try:
            prev = mem.getByte(cur.subtract(1)) & 0xFF
            nxt = mem.getByte(cur.add(4)) & 0xFF
            if prev == 0x68 and nxt == 0x68:
                # next 4 bytes after `68` = opcode
                opc = (mem.getByte(cur.add(5)) & 0xFF) | \
                      ((mem.getByte(cur.add(6)) & 0xFF) << 8) | \
                      ((mem.getByte(cur.add(7)) & 0xFF) << 16) | \
                      ((mem.getByte(cur.add(8)) & 0xFF) << 24)
                return opc
        except Exception:
            pass
        cur = mem.findBytes(cur.add(1), bytes(needle), None, True, monitor)
    return None


def trace(addr, depth, visited):
    """Recursively walk callers. Returns list of (depth, owner_va,
    is_handler, opcode_if_handler) tuples for the chain."""
    if depth > MAX_DEPTH:
        return []
    key = str(addr)
    if key in visited:
        return []
    visited.add(key)

    # Check if THIS function is itself a registered handler.
    fn = fm.getFunctionAt(addr)
    if fn is not None:
        opc = is_handler_registered(addr)
        if opc is not None:
            return [(depth, addr, True, opc)]

    # Else, walk callers.
    refs = list(ref_mgr.getReferencesTo(addr))
    call_refs = [r for r in refs if r.getReferenceType().isCall()]
    results = []
    for r in call_refs:
        owner = fm.getFunctionContaining(r.getFromAddress())
        if owner is None:
            continue
        owner_addr = owner.getEntryPoint()
        # Recurse one level up.
        sub = trace(owner_addr, depth + 1, visited)
        if sub:
            results.append((depth, owner_addr, False, None))
            results.extend(sub)
    return results


out("# Recursive caller-trace for unreached candidates")
out("")
out("For each unreached function, this script walks the static")
out("call graph backwards (depth limit {0}) and looks for a packet".format(MAX_DEPTH))
out("handler in the chain. If found, the unreached function IS")
out("reachable via that handler's internal logic.")
out("")

for va_str in CANDIDATES:
    addr = af.getAddress(va_str)
    fn = fm.getFunctionAt(addr)
    out("## `{0}`".format(va_str))
    out("")
    if fn is None:
        out("(no function defined)")
        out("")
        continue
    chain = trace(addr, 0, set())
    if not chain:
        out("- No reachable handler found within depth {0}.".format(MAX_DEPTH))
        out("")
        continue
    handlers_in_chain = [c for c in chain if c[2]]
    if handlers_in_chain:
        for d, addr_in_chain, _, opc in handlers_in_chain:
            out("- **REACHABLE via opcode 0x{0:04X}** at depth {1}, "
                "registered handler @ {2}".format(opc, d, addr_in_chain))
        # Print the chain back-trace
        out("- Chain: ")
        for d, addr_in_chain, is_h, _ in chain[:20]:
            marker = "HANDLER" if is_h else "intermediate"
            out("    - depth {0} [{1}] @ {2}".format(d, marker, addr_in_chain))
    else:
        out("- No handler-registration in chain (callers traced):")
        for d, addr_in_chain, _, _ in chain[:10]:
            out("    - depth {0} @ {1}".format(d, addr_in_chain))
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
    print("[trace_callers] wrote " + OUT_PATH + " (" + str(len(lines)) + " lines)")
except Exception as e:
    print("[trace_callers] write failed: " + str(e))
    print("\n".join(lines))
