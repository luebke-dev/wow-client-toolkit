# WoW.exe RCE Audit

Program: Wow.exe
ImageBase: 00400000

## Dangerous API call sites


### VirtualAlloc
- 6 call site(s)
  - `00413759` in `___sbh_alloc_new_region` (flag=0x4)
  - `004137e4` in `___sbh_alloc_new_group` (flag=0x4)
  - `0077520a` in `FUN_00775190` (flag=0x4)
  - `0077a318` in `FUN_0077a270` (flag=0x4)
  - `0086fb2d` in `FUN_0086faf0` **PAGE_EXECUTE flag = 0x40**
  - `00872438` in `FUN_00872350` (flag=0x4)
- **executable allocations: 1**
- `VirtualAllocEx`: not imported

### VirtualProtect
- 3 call site(s)
  - `008725da` in `FUN_00872350`
  - `009c56a5` in `VirtualProtect`
  - `009c57fc` in `FUN_009c56e0` **PAGE_EXECUTE flag = 0x40**
- **executable allocations: 1**
- `VirtualProtectEx`: not imported

### LoadLibraryA
- 32 call site(s)
  - `004124ad` in `FUN_00412480`
  - `0041ca6a` in `_LoadGodot@0`
  - `0041ccbe` in `_ResolveThunk@20`
  - `0041ccd1` in `_ResolveThunk@20`
  - `00429389` in `FUN_00429380`
  - `004293e9` in `FUN_004293e0`
  - `00429459` in `FUN_00429450`
  - `0068ed9c` in `FUN_0068ed80`
  - `006a0abc` in `FUN_006a0aa0`
  - `00771079` in `FUN_00771070`
  - `0077cab2` in `FUN_0077ca70`
  - `0077e091` in `FUN_0077e040`
  - `0077e9ae` in `FUN_0077e9a0`
  - `00868c22` in `FUN_00868c10`
  - `00868c82` in `FUN_00868c70`
  - `00868cf2` in `FUN_00868ce0`
  - `0086b71f` in `FUN_0086b710`
  - `0086c4e7` in `FUN_0086c4e0`
  - `0087254d` in `FUN_00872350`
  - `0088879c` in `FUN_00888790`
  - `008a09cc` in `FUN_008a09ba`
  - `008d2073` in `FUN_008d2060`
  - `008f837f` in `FUN_008f8260`
  - `00918b5c` in `FUN_00918a70`
  - `00918ba9` in `FUN_00918a70`
  - `00918bf2` in `FUN_00918a70`
  - `0093ab19` in `FUN_0093aae0`
  - `0093ab32` in `FUN_0093aae0`
  - `009499ef` in `FUN_009499d0`
  - `0095adda` in `FUN_0095ad90`
  - `0095c2fd` in `FUN_0095c190`
  - `009c4ecb` in `FUN_009c4e7d`
- `LoadLibraryW`: not imported
- `LoadLibraryExA`: not imported
- `LoadLibraryExW`: not imported
- `GetProcAddress`: not imported

### CreateProcessA
- 1 call site(s)
  - `00441054` in `FUN_00440d80`

### ShellExecuteA
- 3 call site(s)
  - `00462119` in `FUN_004620a0`
  - `0086b838` in `FUN_0086b790`
  - `0086b982` in `FUN_0086b790`
- `WinExec`: not imported
- `WriteProcessMemory`: not imported

## Warden-related strings

- `.\WardenClient.cpp` @ 00a40774 -- 22 xrefs
  - from `007daa8d` in `FUN_007da9f0`
  - from `007daa3c` in `FUN_007da9f0`
  - from `007da291` in `FUN_007da260`
  - from `007da20e` in `FUN_007da200`
  - from `007da47a` in `FUN_007da420`
  - from `007da503` in `FUN_007da4f0`
  - from `007da519` in `FUN_007da4f0`
  - from `007da4dd` in `FUN_007da4d0`
- `.?AV?$TSExplicitList@UDBCACHEHASH@?$DBCache@VWardenCachedModule@@VCWardenKey@@V2` @ 00ad5b10 -- 4 xrefs
  - from `0066f624` in `FUN_0066f5b0`
  - from `0066de0a` in `FUN_0066dd90`
  - from `0066de28` in `FUN_0066dd90`
  - from `0066ded3` in `FUN_0066dd90`
- `.?AV?$TSExplicitList@UREVERSEENTRY@?$DBCache@VWardenCachedModule@@VCWardenKey@@V` @ 00ad5b80 -- 1 xrefs
  - from `0066f6b4` in `FUN_0066f640`
- `.?AUREVERSEENTRY@?$DBCache@VWardenCachedModule@@VCWardenKey@@V2@@@` @ 00ad6118 -- 2 xrefs
  - from `006718d0` in `FUN_006718c0`
  - from `00671932` in `FUN_00671920`
- `.?AUDBCACHEHASH@?$DBCache@VWardenCachedModule@@VCWardenKey@@V2@@@` @ 00ad6550 -- 2 xrefs
  - from `006791c2` in `FUN_006791b0`
  - from `00671810` in `FUN_00671800`

## CVar / patch URL strings

- `Sound_OutputDriverName` @ 009f2580 -- 3 xrefs
  - from `004c8421` in `FUN_004c82e0`
  - from `004d1348` in `FUN_004d1050`
  - from `004d0e2b` in `FUN_004d0dd0`
- `Sound_DSPBufferSize` @ 009f2cc0 -- 3 xrefs
  - from `0087d4fa` in `FUN_0087c710`
  - from `004d136b` in `FUN_004d1050`
  - from `004d1c74` in `FUN_004d1600`
- `gxApi` @ 00a0c8f4 -- 3 xrefs
  - from `0076adcf` in `FUN_0076ab80`
  - from `0076a832` in `FUN_0076a630`
  - from `0054f1cc` in `FUN_0054f1b0`

## Suspicious function deep-dive


### `FUN_00872350` @ `00872350` -- Manual loader: LoadLibrary + VirtualProtect
**Callers (1):**
- `007da7da` in `FUN_007da610`

```c

bool FUN_00872350(uint *param_1)

{
  byte bVar1;
  uint *puVar2;
  HMODULE pHVar3;
  HANDLE hProcess;
  uint uVar4;
  int *in_ECX;
  int iVar5;
  char *pcVar6;
  char *pcVar7;
  uint *puVar8;
  void *_Dst;
  uint uVar9;
  int *piVar10;
  LPVOID lpAddress;
  char local_458 [29];
  undefined1 local_43b [995];
  DWORD local_58;
  char *local_54;
  void *local_50;
  uint local_4c;
  uint *local_48;
  uint local_44;
  int local_40;
  int local_3c;
  uint *local_38;
  byte *local_34;
  uint local_30;
  uint local_2c;
  uint local_28;
  int *local_24;
  bool local_1d;
  undefined1 *local_1c;
  void *local_14;
  undefined1 *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_00ab2778;
  puStack_10 = &LAB_0040bc70;
  local_14 = ExceptionList;
  local_1c = &stack0xfffffb9c;
  local_40 = 1;
  local_8 = 0;
  uVar9 = *param_1;
  ExceptionList = &local_14;
  in_ECX[1] = uVar9;
  if (uVar9 < 0x80000000) {
    local_24 = in_ECX;
    puVar2 = VirtualAlloc((LPVOID)0x0,uVar9,0x1000,4);
    *in_ECX = (int)puVar2;
    if (puVar2 != (uint *)0x0) {
      puVar8 = param_1;
      for (iVar5 = 10; iVar5 != 0; iVar5 = iVar5 + -1) {
        *puVar2 = *puVar8;
        puVar8 = puVar8 + 1;
        puVar2 = puVar2 + 1;
      }
      piVar10 = (int *)*local_24;
      _Dst = (void *)(param_1[10] + (int)piVar10);
      iVar5 = *piVar10;
      local_1d = true;
      local_38 = param_1 + piVar10[9] * 3 + 10;
      while (local_50 = _Dst, _Dst < (void *)(iVar5 + (int)piVar10)) {
        local_28 = (uint)(ushort)*local_38;
        puVar2 = (uint *)((int)local_38 + 2);
        if (local_1d != false) {
          local_38 = puVar2;
          _memcpy(_Dst,puVar2,local_28);
          puVar2 = (uint *)((int)puVar2 + (local_28 & 0xffff));
        }
        _Dst = (void *)((int)_Dst + (local_28 & 0xffff));
        local_50 = _Dst;
        local_38 = puVar2;
        if ((void *)(iVar5 + (int)piVar10) <= _Dst) break;
        local_1d = local_1d == false;
      }
      local_34 = (byte *)(*(int *)(*local_24 + 8) + *local_24);
      local_3c = 0;
      local_2c = 0;
      while( true ) {
        iVar5 = *local_24;
        if (*(uint *)(iVar5 + 0xc) <= local_2c) break;
        bVar1 = *local_34;
        if ((char)bVar1 < '\0') {
          local_3c = (((bVar1 & 0x7f) * 0x100 + (uint)local_34[1]) * 0x100 + (uint)local_34[2]) *
                     0x100 + (uint)local_34[3];
          local_34 = local_34 + 4;
          *(int *)(iVar5 + local_3c) = *(int *)(iVar5 + local_3c) + iVar5;
          local_2c = local_2c + 1;
        }
        else {
          local_3c = (uint)local_34[1] + local_3c + (uint)bVar1 * 0x100;
          local_34 = local_34 + 2;
          *(int *)(iVar5 + local_3c) = *(int *)(iVar5 + local_3c) + iVar5;
          local_2c = local_2c + 1;
        }
      }
      local_28 = *(int *)(iVar5 + 0x1c) + iVar5;
      piVar10 = local_24;
      for (local_30 = 0; uVar4 = local_28, uVar9 = local_30, local_30 < *(uint *)(*piVar10 + 0x20);
          local_30 = local_30 + 1) {
        pHVar3 = LoadLibraryA((LPCSTR)(*(int *)(local_28 + local_30 * 8) + *piVar10));
        piVar10 = local_24;
        if (pHVar3 == (HMODULE)0x0) goto LAB_00872640;
        puVar2 = (uint *)(*(int *)(uVar4 + 4 + uVar9 * 8) + *local_24);
        while( true ) {
          uVar9 = *puVar2;
          local_48 = puVar2;
          if (uVar9 == 0) break;
          if ((int)uVar9 < 0) {
            uVar9 = (*(code *)PTR_FUN_00b2ed98)(pHVar3,uVar9 & 0x7fffffff);
            *puVar2 = uVar9;
            puVar2 = puVar2 + 1;
          }
          else {
            uVar9 = (*(code *)PTR_FUN_00b2ed98)(pHVar3,*piVar10 + uVar9);
            *puVar2 = uVar9;
            puVar2 = puVar2 + 1;
          }
        }
        piVar10[2] = piVar10[2] + 1;
      }
      uVar9 = 0;
      while( true ) {
        puVar2 = (uint *)*local_24;
        local_4c = uVar9;
        if (puVar2[9] <= uVar9) break;
        puVar8 = param_1 + uVar9 * 3 + 10;
        lpAddress = (LPVOID)(*puVar8 + (int)puVar2);
        local_28 = puVar8[1];
        VirtualProtect(lpAddress,local_28,puVar8[2],&local_58);
        if ((puVar8[2] & 0xf0) != 0) {
          uVar4 = local_28;
          hProcess = GetCurrentProcess();
          FlushInstructionCache(hProcess,lpAddress,uVar4);
        }
        uVar9 = uVar9 + 1;
      }
      uVar9 = puVar2[2];
      if (((uVar9 < *puVar2) && (uVar4 = uVar9 + 0xfff & 0xfffff000, uVar9 <= uVar4)) &&
         (uVar4 < *puVar2)) {
        VirtualFree((LPVOID)((int)puVar2 + uVar4),*puVar2 - uVar4,0x4000);
      }
      local_40 = 0;
    }
  }
  else {
    pcVar6 = "Improper header received: [ ";
    pcVar7 = local_458;
    local_1c = &stack0xfffffb9c;
    for (iVar5 = 7; iVar5 != 0; iVar5 = iVar5 + -1) {
      *(undefined4 *)pcVar7 = *(undefined4 *)pcVar6;
      pcVar6 = pcVar6 + 4;
      pcVar7 = pcVar7 + 4;
    }
    *pcVar7 = *pcVar6;
    _memset(local_43b,0,0x3e3);
    pcVar6 = local_458;
    do {
      pcVar7 = pcVar6;
      pcVar6 = pcVar7 + 1;
    } while (*pcVar7 != '\0');
    uVar9 = 0;
    while( true ) {
      local_54 = pcVar7;
      local_44 = uVar9;
      if (0x1f < uVar9) break;
      _sprintf(pcVar7,"%02X ",(uint)*(byte *)(uVar9 + (int)param_1));
      pcVar6 = pcVar7;
      do {
        pcVar7 = pcVar6;
        pcVar6 = pcVar7 + 1;
      } while (*pcVar7 != '\0');
      uVar9 = uVar9 + 1;
    }
    FUN_00772aa0(local_458);
  }
LAB_00872640:
  iVar5 = local_40;
  local_8 = 0xffffffff;
  if (local_40 != 0) {
    FUN_008722c0();
  }
  ExceptionList = local_14;
  return iVar5 == 0;
}


```

_audit complete_
