# Indirect-reference trace for unreached score-7 candidates

For each function with no static handler-registration site, we list:

- All ghidra references TO the function (any kind: direct call,
  indirect call, data-load).
- Top-level callers reachable transitively.
- A short decompile of any caller that loads the function pointer
  into a slot used as a dispatch target (mov [global+i*4], handler_va).

## `0x006d6d20`

Total references: 1

- ref @ 006def42 (type: UNCONDITIONAL_CALL) in `FUN_006deef0` @ 006deef0
    - instruction: `CALL 0x006d6d20 <- <UNSUPPORTED>`

## `0x006d0240`

Total references: 1

- ref @ 006d7f76 (type: UNCONDITIONAL_CALL) in `FUN_006d7f10` @ 006d7f10
    - instruction: `CALL 0x006d0240 <- <UNSUPPORTED>`

## `0x006d0460`

Total references: 1

- ref @ 006d7f8c (type: UNCONDITIONAL_CALL) in `FUN_006d7f10` @ 006d7f10
    - instruction: `CALL 0x006d0460 <- <UNSUPPORTED>`

## `0x006d0ab0`

Total references: 1

- ref @ 006d7fa2 (type: UNCONDITIONAL_CALL) in `FUN_006d7f10` @ 006d7f10
    - instruction: `CALL 0x006d0ab0 <- <UNSUPPORTED>`

## `0x006d53b0`

Total references: 1

- ref @ 006d854d (type: UNCONDITIONAL_CALL) in `FUN_006d84f0` @ 006d84f0
    - instruction: `CALL 0x006d53b0 <- <UNSUPPORTED>`

## `0x0080e1b0`

Total references: 1

- ref @ 0080ffdc (type: UNCONDITIONAL_CALL) in `FUN_0080fee0` @ 0080fee0
    - instruction: `CALL 0x0080e1b0 <- <UNSUPPORTED>`

## `0x00755630`

Total references: 1

- ref @ 007568b6 (type: UNCONDITIONAL_CALL) in `FUN_00756800` @ 00756800
    - instruction: `CALL 0x00755630 <- <UNSUPPORTED>`

## `0x00753690`

- (no function defined at 0x00753690)

## `0x00768760`

- (no function defined at 0x00768760)
