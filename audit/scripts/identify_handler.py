# -*- coding: utf-8 -*-
# Ghidra Jython 2 script. For a given handler function, walks
# backwards to find:
#   1. Direct callers (chain of one-arg dispatch wrappers)
#   2. Data references (entry in an opcode table = packet handler)
#   3. Surrounding table neighbors (sister handlers in the same
#      dispatch table, useful for opcode-id triangulation)
#
# Inputs (env vars):
#   HANDLER_VA: hex VA of the function to identify (e.g. 0x005a4800)
#   ID_OUT:     output path (default /out/handler_identity.md)
#
# Output: markdown report with identified callers + table neighbors.
# pylint: disable=undefined-variable

# @author wow-client-toolkit
# @category Analysis
# @runtime Jython

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
import os

OUT_PATH = os.environ.get("ID_OUT", "/out/handler_identity.md")
HANDLER_VA = os.environ.get("HANDLER_VA", "0x005a4800")

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


target = af.getAddress(HANDLER_VA)
target_fn = fm.getFunctionAt(target)

out("# Handler identity report -- {0}".format(HANDLER_VA))
out("")
if target_fn is None:
    out("ERROR: no function defined at {0}.".format(HANDLER_VA))
else:
    out("Target function: `{0}` @ {1} (size {2} bytes)".format(
        target_fn.getName(), target_fn.getEntryPoint(),
        target_fn.getBody().getNumAddresses()))
    out("Prototype: `{0}`".format(target_fn.getPrototypeString(False, False)))
    out("")

# ---- 1. Direct callers --------------------------------------------
out("## 1. Direct callers (functions that `call` this handler)")
out("")
refs = ref_mgr.getReferencesTo(target)
call_refs = [r for r in refs if r.getReferenceType().isCall()]
data_refs = [r for r in refs if not r.getReferenceType().isCall()]

if not call_refs:
    out("- (no direct callers; only reached via data ref / dispatch table)")
else:
    for r in call_refs[:20]:
        owner = fm.getFunctionContaining(r.getFromAddress())
        owner_name = owner.getName() if owner else "(no func)"
        owner_addr = str(owner.getEntryPoint()) if owner else "?"
        out("- call from {0} in `{1}` @ {2}".format(
            r.getFromAddress(), owner_name, owner_addr))
out("")

# ---- 2. Data references (handler-table entries) -------------------
out("## 2. Data references (handler-table entries)")
out("")
if not data_refs:
    out("- (no data references; not in a static dispatch table)")
else:
    for r in data_refs[:20]:
        from_addr = r.getFromAddress()
        out("- DATA ref from {0} (type: {1})".format(
            from_addr, r.getReferenceType().getName()))
        # Inspect the surrounding bytes -- if they look like a table
        # entry (e.g. `dword opcode_id; dword name_ptr; dword handler_ptr`)
        # report them.
        try:
            # Try reading 16 bytes before and after the ref site
            # so we can see opcode_id + name_string_ptr + handler_ptr.
            buf_start = from_addr.subtract(16)
            row = []
            for i in range(32):
                b = mem.getByte(buf_start.add(i)) & 0xFF
                row.append("{0:02x}".format(b))
            out("  - 32 bytes around ref site (16 before, 16 after):")
            out("  - `{0}`".format(" ".join(row)))
        except Exception as e:
            out("  - (read failed: {0})".format(e))
out("")

# ---- 3. Possible opcode-table neighbors ---------------------------
# If the data ref is into a table of `(u32 opcode, u32 name_ptr,
# u32 handler_ptr, u32 status)` style entries, the surrounding
# entries are sister handlers. Dump 4 entries before + after.
out("## 3. Possible dispatch-table neighbors")
out("")
if data_refs:
    first_ref = data_refs[0].getFromAddress()
    out("Looking around {0} for 16-byte aligned table-style entries:".format(
        first_ref))
    out("")
    for i in range(-4, 5):
        try:
            addr = first_ref.add(i * 16)
            opcode = mem.getInt(addr) & 0xFFFFFFFF
            name_ptr = mem.getInt(addr.add(4)) & 0xFFFFFFFF
            handler_ptr = mem.getInt(addr.add(8)) & 0xFFFFFFFF
            status = mem.getInt(addr.add(12)) & 0xFFFFFFFF
            out("- entry @ {0}: opcode=0x{1:04x} name_ptr=0x{2:08x} "
                "handler_ptr=0x{3:08x} status=0x{4:08x}".format(
                    addr, opcode, name_ptr, handler_ptr, status))
            # Try reading the name string.
            if 0x00400000 < name_ptr < 0x01000000:
                try:
                    name_addr = af.getAddress("0x{0:08x}".format(name_ptr))
                    s = []
                    for j in range(40):
                        b = mem.getByte(name_addr.add(j)) & 0xFF
                        if b == 0:
                            break
                        if 0x20 <= b < 0x7f:
                            s.append(chr(b))
                        else:
                            s.append("?")
                    out("    - name = `{0}`".format("".join(s)))
                except Exception:
                    pass
        except Exception as e:
            out("- entry @ offset {0}: read failed ({1})".format(i, e))
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
    print("[identify_handler] wrote " + OUT_PATH + " (" + str(len(lines)) + " lines)")
except Exception as e:
    print("[identify_handler] write failed: " + str(e))
    print("\n".join(lines))
