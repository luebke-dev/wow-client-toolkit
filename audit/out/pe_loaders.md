# PE-loader candidates in Wow.exe

Identifies every code path that checks for the `MZ` magic
at offset 0 of a buffer -- candidate sister functions to
`FUN_00872350` (the documented manual PE loader closed by
Patch 2). If any sister loader exists and is not patched, an
attacker can route around Patch 2.

Found 0 unique functions containing an MZ-magic check.

## Functions sorted by loader-shape score

Score = +2 calls VirtualAlloc, +3 calls VirtualProtect, +2 walks
sections (`add reg, 0x28`). >= 5 = full load-then-execute = RCE
primitive. >= 2 = partial PE walk (could just be header-checking).
0 = MZ check exists in code (e.g. an addon validator) but no
dangerous follow-through.


## Top loader candidates decompiled

(no loader-shaped functions found beyond the known FUN_00872350)
