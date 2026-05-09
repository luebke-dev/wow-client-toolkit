# Recursive caller-trace for unreached candidates

For each unreached function, this script walks the static
call graph backwards (depth limit 6) and looks for a packet
handler in the chain. If found, the unreached function IS
reachable via that handler's internal logic.

## `0x006d6d20`

- **REACHABLE via opcode 0x01BC** at depth 1, registered handler @ 006deef0
- Chain: 
    - depth 0 [intermediate] @ 006deef0
    - depth 1 [HANDLER] @ 006deef0

## `0x006d0240`

- **REACHABLE via opcode 0x0185** at depth 1, registered handler @ 006d7f10
- Chain: 
    - depth 0 [intermediate] @ 006d7f10
    - depth 1 [HANDLER] @ 006d7f10

## `0x006d0460`

- **REACHABLE via opcode 0x0185** at depth 1, registered handler @ 006d7f10
- Chain: 
    - depth 0 [intermediate] @ 006d7f10
    - depth 1 [HANDLER] @ 006d7f10

## `0x006d0ab0`

- **REACHABLE via opcode 0x0185** at depth 1, registered handler @ 006d7f10
- Chain: 
    - depth 0 [intermediate] @ 006d7f10
    - depth 1 [HANDLER] @ 006d7f10

## `0x006d53b0`

- **REACHABLE via opcode 0x0160** at depth 1, registered handler @ 006d84f0
- Chain: 
    - depth 0 [intermediate] @ 006d84f0
    - depth 1 [HANDLER] @ 006d84f0

## `0x0080e1b0`

- **REACHABLE via opcode 0x0131** at depth 1, registered handler @ 0080fee0
- Chain: 
    - depth 0 [intermediate] @ 0080fee0
    - depth 1 [HANDLER] @ 0080fee0

## `0x00755630`

- **REACHABLE via opcode 0x0143** at depth 1, registered handler @ 00756800
- Chain: 
    - depth 0 [intermediate] @ 00756800
    - depth 1 [HANDLER] @ 00756800

## `0x004d7100`

- **REACHABLE via opcode 0x00A9** at depth 1, registered handler @ 004d73a0
- Chain: 
    - depth 0 [intermediate] @ 004d73a0
    - depth 1 [HANDLER] @ 004d73a0

## `0x004e5a50`

- No reachable handler found within depth 6.

## `0x00503990`

- **REACHABLE via opcode 0x009B** at depth 1, registered handler @ 00505dc0
- Chain: 
    - depth 0 [intermediate] @ 00505dc0
    - depth 1 [HANDLER] @ 00505dc0

## `0x0050be70`

- **REACHABLE via opcode 0x0096** at depth 1, registered handler @ 0050eba0
- **REACHABLE via opcode 0x03B3** at depth 1, registered handler @ 0050ebc0
- Chain: 
    - depth 0 [intermediate] @ 0050eba0
    - depth 1 [HANDLER] @ 0050eba0
    - depth 0 [intermediate] @ 0050ebc0
    - depth 1 [HANDLER] @ 0050ebc0

## `0x005c29c0`

- **REACHABLE via opcode 0x0436** at depth 1, registered handler @ 005c3fe0
- Chain: 
    - depth 0 [intermediate] @ 005c3fe0
    - depth 1 [HANDLER] @ 005c3fe0

## `0x005f79a0`

- **REACHABLE via opcode 0x01EC** at depth 2, registered handler @ 00464f50
- Chain: 
    - depth 0 [intermediate] @ 00464410
    - depth 1 [intermediate] @ 00464f50
    - depth 2 [HANDLER] @ 00464f50

## `0x006b8720`

- No reachable handler found within depth 6.

## `0x006cdf30`

- **REACHABLE via opcode 0x0115** at depth 1, registered handler @ 006ce070
- **REACHABLE via opcode 0x03F4** at depth 1, registered handler @ 006ce0c0
- Chain: 
    - depth 0 [intermediate] @ 006ce070
    - depth 1 [HANDLER] @ 006ce070
    - depth 0 [intermediate] @ 006ce0c0
    - depth 1 [HANDLER] @ 006ce0c0

## `0x0073c8e0`

- **REACHABLE via opcode 0x00DD** at depth 3, registered handler @ 0073f590
- **REACHABLE via opcode 0x031A** at depth 5, registered handler @ 00741c30
- **REACHABLE via opcode 0x00A9** at depth 6, registered handler @ 004d73a0
- **REACHABLE via opcode 0x00B5** at depth 6, registered handler @ 00741b60
- Chain: 
    - depth 0 [intermediate] @ 00747990
    - depth 1 [intermediate] @ 0074c040
    - depth 2 [intermediate] @ 0073f590
    - depth 3 [HANDLER] @ 0073f590
    - depth 1 [intermediate] @ 00748230
    - depth 2 [intermediate] @ 006ed7e0
    - depth 3 [intermediate] @ 00740ba0
    - depth 4 [intermediate] @ 00741c30
    - depth 5 [HANDLER] @ 00741c30
    - depth 2 [intermediate] @ 00749aa0
    - depth 3 [intermediate] @ 00749cb0
    - depth 4 [intermediate] @ 004d7230
    - depth 5 [intermediate] @ 004d73a0
    - depth 6 [HANDLER] @ 004d73a0
    - depth 2 [intermediate] @ 0074be10
    - depth 3 [intermediate] @ 007189a0
    - depth 4 [intermediate] @ 00740d30
    - depth 5 [intermediate] @ 00741b60
    - depth 6 [HANDLER] @ 00741b60
