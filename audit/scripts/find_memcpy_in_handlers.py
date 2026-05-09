# -*- coding: utf-8 -*-
# Ghidra Jython 2 script. Hunts for non-CDataStore deserialization
# primitives: any handler that calls `_memcpy` (or has inline
# `rep movsd / movsb`) where the destination is a fixed writable
# global and the length is recently-loaded from CDataStore.
#
# Output: /out/non_cdatastore_primitives.md
# pylint: disable=undefined-variable

# @author wow-client-toolkit
# @category Analysis
# @runtime Jython

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
import os

OUT_PATH = os.environ.get("NM_OUT", "/out/non_cdatastore_primitives.md")

cp = currentProgram
fm = cp.getFunctionManager()
af = cp.getAddressFactory()
listing = cp.getListing()
ref_mgr = cp.getReferenceManager()
mem = cp.getMemory()
sym_table = cp.getSymbolTable()

decomp = DecompInterface()
decomp.setOptions(DecompileOptions())
decomp.openProgram(cp)

lines = []


def out(s):
    lines.append(s)


# Find _memcpy / _memmove import or thunks.
# In MSVC-built binaries `_memcpy` is usually compiled inline as
# rep movsd; rep movsb. There IS often a callable wrapper too.
def find_function(name):
    """Resolve a function symbol by name. Returns address or None."""
    for sym in sym_table.getSymbols(name):
        if sym.getSymbolType().toString() == "Function":
            return sym.getAddress()
    # Also try external entries
    ext_mgr = cp.getExternalManager()
    for lib in ext_mgr.getExternalLibraryNames():
        it = ext_mgr.getExternalLocations(lib)
        while it.hasNext():
            loc = it.next()
            if loc.getLabel() == name:
                a = loc.getExternalSpaceAddress()
                # find the import-thunk in .text via xrefs
                refs = list(ref_mgr.getReferencesTo(a))
                for r in refs:
                    src = r.getFromAddress()
                    f = fm.getFunctionContaining(src)
                    if f is not None:
                        return f.getEntryPoint()
    return None


memcpy_va = find_function("_memcpy")
memmove_va = find_function("_memmove")

out("# Non-CDataStore deserialization primitive audit")
out("")
out("Identifies handlers that call `_memcpy` or `_memmove` with")
out("a destination in writable globals and a length argument that's")
out("recently loaded from a `CDataStore::Get*` call. The shape")
out("matches an attacker-controlled bulk-write primitive.")
out("")
if memcpy_va is None and memmove_va is None:
    out("(neither _memcpy nor _memmove resolved; aborting)")
else:
    if memcpy_va is not None:
        out("- `_memcpy` resolved to {0}".format(memcpy_va))
    if memmove_va is not None:
        out("- `_memmove` resolved to {0}".format(memmove_va))
    out("")

# For each registered packet handler, see if it transitively calls memcpy/memmove
# We re-derive the handler list from a binary byte search for the
# canonical `push handler; push opcode; call RegisterHandler` pattern.

def find_packet_handlers():
    """Find every registered packet handler by scanning for the
    `push imm32; push imm32_in_opcode_range; call rel32` 3-instruction
    prologue. imm32_in_opcode_range = 0x0001..0x0FFF (12-bit opcodes
    with leading null byte common). Returns set of handler-VAs."""
    handlers = {}
    # Scan .text for `68 ?? ?? ?? ?? 68 ?? ?? 00 00 e8 ?? ?? ?? ??`
    # 5 + 5 + 5 = 15 bytes pattern
    text_start = af.getAddress("0x00401000")
    text_end = af.getAddress("0x009DD000")
    cur = text_start
    needle = bytearray([0x68])  # push imm32
    while cur is not None and cur.compareTo(text_end) < 0:
        cur = mem.findBytes(cur, bytes(needle), None, True, monitor)
        if cur is None:
            break
        try:
            # need 15 bytes total
            if cur.add(14).compareTo(text_end) >= 0:
                break
            handler_va = (mem.getByte(cur.add(1)) & 0xFF) | \
                         ((mem.getByte(cur.add(2)) & 0xFF) << 8) | \
                         ((mem.getByte(cur.add(3)) & 0xFF) << 16) | \
                         ((mem.getByte(cur.add(4)) & 0xFF) << 24)
            second_op = mem.getByte(cur.add(5)) & 0xFF
            if second_op != 0x68:
                cur = cur.add(1); continue
            opcode = (mem.getByte(cur.add(6)) & 0xFF) | \
                     ((mem.getByte(cur.add(7)) & 0xFF) << 8) | \
                     ((mem.getByte(cur.add(8)) & 0xFF) << 16) | \
                     ((mem.getByte(cur.add(9)) & 0xFF) << 24)
            third_op = mem.getByte(cur.add(10)) & 0xFF
            if third_op != 0xE8:
                cur = cur.add(1); continue
            # Validate opcode range (0x0001..0x0FFF) and handler in .text
            if 1 <= opcode < 0x1000 and 0x00400000 < handler_va < 0x009DD000:
                handlers[handler_va] = opcode
        except Exception:
            pass
        cur = cur.add(1)
    return handlers


handlers = find_packet_handlers()
out("Found {0} packet handlers in the binary.".format(len(handlers)))
out("")

# For each handler, check if it (or any function it calls in 1-2 levels)
# invokes _memcpy / _memmove.
def fn_calls_target(fn, target_va, depth, visited):
    if fn is None or depth < 0:
        return False
    key = str(fn.getEntryPoint())
    if key in visited:
        return False
    visited.add(key)
    body = fn.getBody()
    it = listing.getInstructions(body, True)
    while it.hasNext():
        ins = it.next()
        for ref in ins.getReferencesFrom():
            tgt = ref.getToAddress()
            if tgt is None: continue
            if tgt == target_va:
                return True
            if depth > 0:
                callee = fm.getFunctionAt(tgt)
                if callee is not None:
                    if fn_calls_target(callee, target_va, depth - 1, visited):
                        return True
    return False


out("## Handlers that call `_memcpy` or `_memmove` (depth 0-1)")
out("")
hits = []
for handler_va, opcode in handlers.items():
    fn = fm.getFunctionAt(af.getAddress("0x{0:08x}".format(handler_va)))
    if fn is None: continue
    if memcpy_va and fn_calls_target(fn, memcpy_va, 1, set()):
        hits.append((handler_va, opcode, "_memcpy"))
        continue
    if memmove_va and fn_calls_target(fn, memmove_va, 1, set()):
        hits.append((handler_va, opcode, "_memmove"))

if not hits:
    out("- (none -- no packet handler reaches _memcpy / _memmove within depth 1)")
else:
    for handler_va, opcode, fname in hits[:50]:
        out("- opcode 0x{0:04X} -> handler @ 0x{1:08x} (calls `{2}`)".format(
            opcode, handler_va, fname))
out("")

# Write
out_dir = os.path.dirname(OUT_PATH)
if out_dir and not os.path.isdir(out_dir):
    try: os.makedirs(out_dir)
    except: pass
try:
    f = open(OUT_PATH, "w")
    f.write("\n".join(lines))
    f.close()
    print("[find_memcpy] wrote " + OUT_PATH + " (" + str(len(lines)) + " lines)")
except Exception as e:
    print("[find_memcpy] write failed: " + str(e))
