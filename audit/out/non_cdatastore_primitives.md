# Non-CDataStore deserialization primitive audit

Identifies handlers that call `_memcpy` or `_memmove` with
a destination in writable globals and a length argument that's
recently loaded from a `CDataStore::Get*` call. The shape
matches an attacker-controlled bulk-write primitive.

- `_memcpy` resolved to 0040cb10
- `_memmove` resolved to 00414760

Found 289 packet handlers in the binary.

## Handlers that call `_memcpy` or `_memmove` (depth 0-1)

- opcode 0x0244 -> handler @ 0x00635a40 (calls `_memcpy`)
- opcode 0x0203 -> handler @ 0x006e7840 (calls `_memcpy`)
- opcode 0x020E -> handler @ 0x0052c460 (calls `_memcpy`)
- opcode 0x012C -> handler @ 0x006e7e00 (calls `_memcpy`)
- opcode 0x028D -> handler @ 0x005a0ac0 (calls `_memmove`)
- opcode 0x03F1 -> handler @ 0x005042f0 (calls `_memmove`)
- opcode 0x0496 -> handler @ 0x007300a0 (calls `_memcpy`)
- opcode 0x025E -> handler @ 0x005a0480 (calls `_memmove`)
- opcode 0x03C5 -> handler @ 0x004d9500 (calls `_memcpy`)
- opcode 0x04FA -> handler @ 0x00526530 (calls `_memcpy`)
- opcode 0x044A -> handler @ 0x00576730 (calls `_memcpy`)
- opcode 0x00FD -> handler @ 0x00530920 (calls `_memcpy`)
- opcode 0x039E -> handler @ 0x006ccf10 (calls `_memcpy`)
- opcode 0x025F -> handler @ 0x005a0790 (calls `_memmove`)
- opcode 0x0239 -> handler @ 0x005717b0 (calls `_memcpy`)
- opcode 0x017D -> handler @ 0x0058b1b0 (calls `_memcpy`)
- opcode 0x025B -> handler @ 0x0059ffb0 (calls `_memmove`)
