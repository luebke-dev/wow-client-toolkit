# -*- coding: utf-8 -*-
# Ghidra headless audit script for WoW.exe RCE hunting.
# Lists call sites of VirtualAlloc / VirtualProtect with RWX (PAGE_EXECUTE_READWRITE = 0x40)
# and LoadLibraryA/W call sites with their resolved 1st argument when statically determinable.
# Also reports xrefs to Warden-related strings and known dangerous APIs.
#
# Run via: analyzeHeadless <project> <name> -import Wow.exe -postScript audit_rce.py -scriptPath /scripts
#
# Output is appended to /out/audit.md (mounted from host).

# @author audit
# @category Analysis
# @runtime Jython

import os

from ghidra.program.model.symbol import RefType, SymbolType
from ghidra.program.model.address import Address
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.scalar import Scalar
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

OUT_PATH = "/out/audit.md"
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_WRITECOPY = 0x80
EXEC_FLAGS = {0x10, 0x20, 0x40, 0x80}

DANGEROUS_APIS = [
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress",
    "CreateProcessA", "CreateProcessW",
    "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
    "WinExec", "FindExecutableA",
    "WriteProcessMemory",
    "system", "_wsystem",
]

WARDEN_STRINGS = [
    "WardenCachedModule", "WardenKey", "Warden",
]

CVAR_INTEREST_STRINGS = [
    "Sound_OutputDriverName", "Sound_DSPBufferSize", "gxApi",
    "patchurl", "PatchUrl", "PatchURL",
]


def out_write(lines):
    with open(OUT_PATH, "a") as f:
        for line in lines:
            try:
                f.write(line + "\n")
            except UnicodeEncodeError:
                f.write(line.encode("ascii", "replace") + "\n")


def safe_str(v):
    try:
        s = unicode(v) if not isinstance(v, str) else v
    except Exception:
        return repr(v)
    return s.encode("ascii", "replace")


def find_external_function(name):
    fm = currentProgram.getFunctionManager()
    for f in fm.getExternalFunctions():
        if f.getName() == name:
            return f
    # Fallback: check thunks / imports table by symbol
    st = currentProgram.getSymbolTable()
    for sym in st.getSymbols(name):
        if sym.getSymbolType() in (SymbolType.FUNCTION, SymbolType.LABEL):
            f = fm.getFunctionAt(sym.getAddress())
            if f is not None:
                return f
    return None


def get_callers(func):
    callers = []
    if func is None:
        return callers
    refs = getReferencesTo(func.getEntryPoint())
    for r in refs:
        if r.getReferenceType().isCall() or r.getReferenceType().isJump():
            callers.append(r.getFromAddress())
    # Thunks: include refs to thunked address
    fm = currentProgram.getFunctionManager()
    for f in fm.getFunctions(True):
        if f.isThunk() and f.getThunkedFunction(True) == func:
            for r in getReferencesTo(f.getEntryPoint()):
                if r.getReferenceType().isCall() or r.getReferenceType().isJump():
                    callers.append(r.getFromAddress())
    return list(set(callers))


def decompile_function_at(addr):
    fm = currentProgram.getFunctionManager()
    f = fm.getFunctionContaining(addr)
    if f is None:
        return None, None
    di = DecompInterface()
    di.setOptions(DecompileOptions())
    di.openProgram(currentProgram)
    res = di.decompileFunction(f, 60, ConsoleTaskMonitor())
    if res is None or not res.decompileCompleted():
        return f, None
    return f, res.getDecompiledFunction().getC()


def constants_pushed_before(call_addr, count):
    """Walk back up to ~24 instructions, collect PUSH-immediate values (x86 cdecl/stdcall)."""
    listing = currentProgram.getListing()
    instr = listing.getInstructionAt(call_addr)
    if instr is None:
        return []
    pushed = []
    cur = instr.getPrevious()
    walked = 0
    while cur is not None and walked < 32 and len(pushed) < count:
        mnem = cur.getMnemonicString().upper()
        if mnem == "PUSH":
            ops = cur.getOpObjects(0)
            if ops and isinstance(ops[0], Scalar):
                pushed.append(ops[0].getUnsignedValue())
            else:
                pushed.append(None)
        elif mnem == "CALL":
            break
        cur = cur.getPrevious()
        walked += 1
    return pushed


def audit_api_callers(api_name, exec_flag_arg_index=None):
    fn = find_external_function(api_name)
    if fn is None:
        return ["- `%s`: not imported" % api_name]
    lines = ["", "### %s" % api_name]
    callers = get_callers(fn)
    lines.append("- %d call site(s)" % len(callers))
    flagged = 0
    for ca in sorted(callers, key=lambda a: a.getOffset()):
        pushed = constants_pushed_before(ca, 6)
        info = ""
        if exec_flag_arg_index is not None and len(pushed) > exec_flag_arg_index:
            v = pushed[exec_flag_arg_index]
            if v is not None and v in EXEC_FLAGS:
                info = " **PAGE_EXECUTE flag = 0x%X**" % v
                flagged += 1
            elif v is not None:
                info = " (flag=0x%X)" % v
        containing = currentProgram.getFunctionManager().getFunctionContaining(ca)
        cname = containing.getName() if containing else "?"
        lines.append("  - `%s` in `%s`%s" % (ca, cname, info))
    if exec_flag_arg_index is not None:
        lines.append("- **executable allocations: %d**" % flagged)
    return lines


def audit_strings(needles):
    lines = []
    listing = currentProgram.getListing()
    mem = currentProgram.getMemory()
    for s in listing.getDefinedData(True):
        try:
            val = s.getValue()
        except Exception:
            continue
        if val is None:
            continue
        sval = safe_str(val)
        for n in needles:
            if n in sval:
                refs = getReferencesTo(s.getAddress())
                callers = []
                for r in refs:
                    if r.getReferenceType().isData() or r.getReferenceType().isRead():
                        f = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress())
                        callers.append((r.getFromAddress(), f.getName() if f else "?"))
                lines.append("- `%s` @ %s -- %d xrefs" % (sval[:80], s.getAddress(), len(callers)))
                for fa, fn in callers[:8]:
                    lines.append("  - from `%s` in `%s`" % (fa, fn))
                break
    return lines


def main():
    out_write(["# WoW.exe RCE Audit", "",
               "Program: %s" % currentProgram.getName(),
               "ImageBase: %s" % currentProgram.getImageBase(),
               ""])

    out_write(["## Dangerous API call sites", ""])
    # x86 stdcall/cdecl pushes args right-to-left.
    # The LAST push immediately before CALL holds arg0.
    # constants_pushed_before walks backward, so pushed[0]=arg0, pushed[3]=arg3 (flProtect for VirtualAlloc).
    out_write(audit_api_callers("VirtualAlloc", exec_flag_arg_index=3))
    out_write(audit_api_callers("VirtualAllocEx", exec_flag_arg_index=4))
    # VirtualProtect(lpAddr, dwSize, flNewProtect, lpflOldProtect) -> arg2
    out_write(audit_api_callers("VirtualProtect", exec_flag_arg_index=2))
    out_write(audit_api_callers("VirtualProtectEx", exec_flag_arg_index=3))

    for api in ["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
                "GetProcAddress", "CreateProcessA", "ShellExecuteA", "WinExec",
                "WriteProcessMemory"]:
        out_write(audit_api_callers(api))

    out_write(["", "## Warden-related strings", ""])
    out_write(audit_strings(WARDEN_STRINGS))

    out_write(["", "## CVar / patch URL strings", ""])
    out_write(audit_strings(CVAR_INTEREST_STRINGS))

    # Deep dive on the suspicious RWX-related functions identified in the first run.
    suspects = [
        ("00872350", "Manual loader: LoadLibrary + VirtualProtect"),
    ]
    out_write(["", "## Suspicious function deep-dive", ""])
    af = currentProgram.getAddressFactory()
    fm = currentProgram.getFunctionManager()
    for hexaddr, label in suspects:
        addr = af.getAddress(hexaddr)
        f = fm.getFunctionAt(addr)
        if f is None:
            f = fm.getFunctionContaining(addr)
        if f is None:
            out_write(["### %s (%s) -- function not found" % (hexaddr, label)])
            continue
        out_write(["", "### `%s` @ `%s` -- %s" % (f.getName(), f.getEntryPoint(), label)])
        # Caller chain (1 level)
        callers = []
        for r in getReferencesTo(f.getEntryPoint()):
            if r.getReferenceType().isCall() or r.getReferenceType().isJump():
                cf = fm.getFunctionContaining(r.getFromAddress())
                callers.append((r.getFromAddress(), cf.getName() if cf else "?"))
        out_write(["**Callers (%d):**" % len(callers)])
        for fa, fn in callers[:20]:
            out_write(["- `%s` in `%s`" % (fa, fn)])
        # Decompile body
        _, csrc = decompile_function_at(f.getEntryPoint())
        if csrc:
            out_write(["", "```c"])
            for ln in csrc.split("\n"):
                out_write([safe_str(ln)])
            out_write(["```"])

    out_write(["", "_audit complete_"])


main()
