# -*- coding: utf-8 -*-
# Ghidra Jython 2 script. Find addresses our runtime DLL wants
# to hook for full Warden-attack visibility:
#   1. FrameScript::Execute (the writeup's 0x00419210 reference)
#   2. ClientServices::SetMessageHandler (writeup's payload uses this
#      to register CMSG_UNUSED5 as covert C2)
#   3. Win32 IAT entries we'd hook to trace shellcode behavior
#
# Output: /out/warden_targets.md
# pylint: disable=undefined-variable

# @author wow-exe-patcher
# @category Analysis
# @runtime Jython

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
import os

OUT_PATH = os.environ.get("WT_OUT", "/out/warden_targets.md")

cp = currentProgram
mem = cp.getMemory()
fm = cp.getFunctionManager()
af = cp.getAddressFactory()
sym_table = cp.getSymbolTable()

decomp = DecompInterface()
decomp.setOptions(DecompileOptions())
decomp.openProgram(cp)

lines = []


def out(s):
    lines.append(s)


out("# Warden-attack target functions in Wow.exe")
out("")
out("Auto-discovered by `find_warden_targets.py` postscript.")
out("")

# ---- 1. FrameScript::Execute ---------------------------------------
out("## 1. FrameScript::Execute (writeup-asserted 0x00419210)")
out("")

asserted = af.getAddress("0x00419210")
fn = fm.getFunctionContaining(asserted)
if fn is not None:
    out("- Function containing 0x00419210: **`{0}`** @ `{1}`".format(
        fn.getName(), fn.getEntryPoint()))
    out("- Signature: `{0}`".format(fn.getPrototypeString(False, False)))
    out("- Size: {0} bytes".format(fn.getBody().getNumAddresses()))
    out("")
    out("Decompile (first 80 lines):")
    out("```c")
    res = decomp.decompileFunction(fn, 60, ConsoleTaskMonitor())
    if res.decompileCompleted():
        c = res.getDecompiledFunction().getC()
        for ln in c.splitlines()[:80]:
            out(ln)
    out("```")
else:
    out("- No function defined at 0x00419210.")
out("")

# ---- 2. CMSG_UNUSED5 (0x041F) push references ---------------------
out("## 2. ClientServices::SetMessageHandler (CMSG_UNUSED5 = 0x041F)")
out("")
out("Heuristic: search for `push 0x041F` (5 bytes 68 1F 04 00 00).")
out("The writeup's payload calls SetMessageHandler with this opcode")
out("to register a covert C2 channel. Any function that pushes this")
out("constant is a candidate caller of SetMessageHandler.")
out("")

needle = bytearray([0x68, 0x1F, 0x04, 0x00, 0x00])
addr = mem.findBytes(cp.getMinAddress(), bytes(needle), None, True, monitor)
hits = 0
while addr is not None and hits < 20:
    f = fm.getFunctionContaining(addr)
    if f:
        out("- push 0x041F @ {0} (in `{1}` @ {2})".format(
            addr, f.getName(), f.getEntryPoint()))
        hits += 1
    addr = mem.findBytes(addr.add(1), bytes(needle), None, True, monitor)
if hits == 0:
    out("- No `push 0x041F` found.")
out("")

# ---- 3. Win32 IAT entries (shellcode tracing) ---------------------
out("## 3. Win32 IAT entries to hook (shellcode behavior tracing)")
out("")
WANT = [
    "VirtualAlloc", "VirtualProtect",
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "CreateProcessA", "CreateProcessW",
    "ShellExecuteA", "ShellExecuteW",
    "WinExec", "URLDownloadToFileA",
    "WriteFile", "RegSetValueExA",
    "WSAStartup", "socket", "connect", "send", "recv",
    "FreeLibrary", "ExitProcess",
    "VirtualAllocEx", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread",
]
for name in WANT:
    syms = list(sym_table.getSymbols(name))
    found_any = False
    for s in syms:
        # Only report the import-thunk symbol address
        addr_str = str(s.getAddress())
        kind = s.getSymbolType().toString() if s.getSymbolType() else "?"
        out("- `{0}`: {1} ({2})".format(name, addr_str, kind))
        found_any = True
    if not found_any:
        out("- `{0}`: NOT in IAT (would need GetProcAddress at runtime)".format(name))
out("")

# Also dump every imported function to a section so we know the
# real import set the shellcode could pivot through.
out("## 4. Full import set")
out("")
out("```")
ext_mgr = cp.getExternalManager()
for lib_name in ext_mgr.getExternalLibraryNames():
    out("[" + lib_name + "]")
    iter_syms = ext_mgr.getExternalLocations(lib_name)
    while iter_syms.hasNext():
        loc = iter_syms.next()
        out("  " + str(loc.getLabel()))
out("```")

# Write report
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
    print("[find_warden_targets] wrote " + OUT_PATH + " (" + str(len(lines)) + " lines)")
except Exception as e:
    print("[find_warden_targets] write failed: " + str(e))
    print("\n".join(lines))
