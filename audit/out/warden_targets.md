# Warden-attack target functions in Wow.exe

Auto-discovered by `find_warden_targets.py` postscript.

## 1. FrameScript::Execute (writeup-asserted 0x00419210)

- Function containing 0x00419210: **`FUN_00418c34`** @ `00418c34`
- Signature: `undefined FUN_00418c34()`
- Size: 1680 bytes

Decompile (first 80 lines):
```c

void FUN_00418c34(undefined2 *param_1,int *param_2,char *param_3,int param_4,int param_5,int param_6
                 ,int param_7,int *param_8)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  bool bVar6;
  bool bVar7;
  bool bVar8;
  ushort uVar9;
  char cVar10;
  ushort uVar11;
  undefined4 *puVar12;
  uint uVar13;
  ushort *puVar14;
  int iVar15;
  ushort uVar16;
  int iVar17;
  uint uVar18;
  ushort uVar19;
  char *pcVar20;
  undefined4 uVar21;
  undefined *puVar22;
  short *psVar23;
  uint uVar24;
  undefined4 uVar25;
  ushort uVar26;
  char *pcVar27;
  int local_6c;
  int local_68;
  ushort *local_64;
  ushort *local_60;
  int local_5c;
  char *local_58;
  int local_54;
  uint local_50;
  ushort local_4c;
  undefined4 uStack_4a;
  undefined2 uStack_46;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  ushort uStack_38;
  ushort local_36;
  byte local_30;
  undefined1 uStack_2f;
  undefined4 uStack_2e;
  undefined4 uStack_2a;
  ushort uStack_26;
  char local_24 [23];
  char local_d;
  uint local_8;
  
  local_8 = DAT_00ab6994 ^ (uint)&stack0xfffffffc;
  iVar17 = 0;
  pcVar27 = local_24;
  uVar9 = 0;
  local_6c = 1;
  local_50 = 0;
  bVar6 = false;
  bVar8 = false;
  bVar7 = false;
  local_68 = 0;
  local_54 = 0;
  if (param_8 != (int *)0x0) {
    local_58 = param_3;
    for (; (((cVar10 = *param_3, cVar10 == ' ' || (cVar10 == '\t')) || (cVar10 == '\n')) ||
           (cVar10 == '\r')); param_3 = param_3 + 1) {
    }
LAB_00418cb9:
    cVar10 = *param_3;
    pcVar20 = param_3 + 1;
    switch(iVar17) {
    case 0:
      if ((byte)(cVar10 - 0x31U) < 9) {
LAB_00418cd6:
```

## 2. ClientServices::SetMessageHandler (CMSG_UNUSED5 = 0x041F)

Heuristic: search for `push 0x041F` (5 bytes 68 1F 04 00 00).
The writeup's payload calls SetMessageHandler with this opcode
to register a covert C2 channel. Any function that pushes this
constant is a candidate caller of SetMessageHandler.

- push 0x041F @ 0040ae60 (in `FUN_0040ae30` @ 0040ae30)
- push 0x041F @ 004f9f81 (in `FUN_004f9f70` @ 004f9f70)
- push 0x041F @ 005294ea (in `FUN_00529160` @ 00529160)
- push 0x041F @ 0052b705 (in `FUN_0052b550` @ 0052b550)

## 3. Win32 IAT entries to hook (shellcode behavior tracing)

- `VirtualAlloc`: EXTERNAL:00000049 (Function)
- `VirtualProtect`: EXTERNAL:0000005e (Function)
- `LoadLibraryA`: EXTERNAL:0000004d (Function)
- `LoadLibraryW`: NOT in IAT (would need GetProcAddress at runtime)
- `GetProcAddress`: NOT in IAT (would need GetProcAddress at runtime)
- `CreateProcessA`: EXTERNAL:00000096 (Function)
- `CreateProcessW`: NOT in IAT (would need GetProcAddress at runtime)
- `ShellExecuteA`: EXTERNAL:000001a2 (Function)
- `ShellExecuteW`: NOT in IAT (would need GetProcAddress at runtime)
- `WinExec`: NOT in IAT (would need GetProcAddress at runtime)
- `URLDownloadToFileA`: NOT in IAT (would need GetProcAddress at runtime)
- `WriteFile`: EXTERNAL:00000025 (Function)
- `RegSetValueExA`: EXTERNAL:0000019a (Function)
- `WSAStartup`: NOT in IAT (would need GetProcAddress at runtime)
- `socket`: NOT in IAT (would need GetProcAddress at runtime)
- `connect`: NOT in IAT (would need GetProcAddress at runtime)
- `send`: NOT in IAT (would need GetProcAddress at runtime)
- `recv`: NOT in IAT (would need GetProcAddress at runtime)
- `FreeLibrary`: EXTERNAL:0000004f (Function)
- `ExitProcess`: EXTERNAL:00000026 (Function)
- `VirtualAllocEx`: NOT in IAT (would need GetProcAddress at runtime)
- `VirtualProtectEx`: NOT in IAT (would need GetProcAddress at runtime)
- `WriteProcessMemory`: NOT in IAT (would need GetProcAddress at runtime)
- `ReadProcessMemory`: NOT in IAT (would need GetProcAddress at runtime)
- `CreateRemoteThread`: NOT in IAT (would need GetProcAddress at runtime)

## 4. Full import set

```
[KERNEL32.DLL]
  ExitProcess
  ExitThread
  Module32First
  Module32Next
  CreateToolhelp32Snapshot
  Thread32Next
  Thread32First
  RtlUnwind
  GetCurrentThreadId
  GetCurrentProcessId
  GetACP
  TlsAlloc
  FreeLibrary
  CloseHandle
  GetCurrentProcess
  VirtualProtect
  IsBadWritePtr
  FlushInstructionCache
  SwitchToFiber
  ConvertThreadToFiber
  CreateFiberEx
  DeleteFiber
  GetStartupInfoA
  GetProcessHeap
  HeapAlloc
  GetVersionExA
  HeapFree
  GetCommandLineA
  IsDebuggerPresent
  SetUnhandledExceptionFilter
  UnhandledExceptionFilter
  TerminateProcess
  GetModuleHandleA
  GetModuleFileNameA
  GetStdHandle
  WriteFile
  GetLastError
  GetEnvironmentStrings
  FreeEnvironmentStringsA
  GetFileType
  SetHandleCount
  TlsGetValue
  TlsSetValue
  TlsFree
  InterlockedIncrement
  SetLastError
  HeapCreate
  HeapDestroy
  GetSystemTimeAsFileTime
  GetTickCount
  QueryPerformanceCounter
  VirtualQuery
  Sleep
  HeapSize
  RaiseException
  DeleteCriticalSection
  LeaveCriticalSection
  EnterCriticalSection
  InitializeCriticalSection
  LoadLibraryA
  InterlockedDecrement
  GetOEMCP
  VirtualFree
  HeapReAlloc
  VirtualAlloc
  SetFilePointer
  GetConsoleMode
  GetConsoleCP
  LCMapStringA
  GetStringTypeA
  GetTimeFormatA
  SetStdHandle
  GetConsoleOutputCP
  WriteConsoleA
  GetLocaleInfoA
  GetTimeZoneInformation
  CreateFileA
  FlushFileBuffers
  CompareStringA
  SetEnvironmentVariableA
  GetSystemDirectoryA
  GetWindowsDirectoryA
  InterlockedExchange
  SetEvent
  WaitForSingleObject
  SetThreadPriority
  GetThreadPriority
  SignalObjectAndWait
  GetCurrentThread
  FileTimeToSystemTime
  SystemTimeToFileTime
  FindResourceExA
  LoadResource
  LockResource
  SizeofResource
  QueryPerformanceFrequency
  GetSystemInfo
  GetDiskFreeSpaceA
  ReadFile
  GetFileSize
  GetFileAttributesExA
  GetFileAttributesA
  MoveFileA
  DeleteFileA
  CreateEventA
  GetComputerNameA
  WaitForSingleObjectEx
  CreateProcessA
  SetThreadAffinityMask
  DuplicateHandle
  GetProcessAffinityMask
  SetCurrentDirectoryA
  GetCurrentDirectoryA
  FindFirstFileA
  FindNextFileA
  FindClose
  GetShortPathNameA
  GetDiskFreeSpaceExA
  CreateDirectoryA
  RemoveDirectoryA
  SetEndOfFile
  SetFileTime
  SetFileAttributesA
  WaitForMultipleObjects
  ResetEvent
  SetProcessAffinityMask
  CreateThread
  GetLocalTime
  FormatMessageA
  GetVersion
  GetExitCodeProcess
  OutputDebugStringA
  ReleaseSemaphore
  CreateMutexA
  ReleaseMutex
  CreateSemaphoreA
  IsBadReadPtr
  lstrcpynA
  OpenThread
  SuspendThread
  GetThreadContext
  ResumeThread
  GetPriorityClass
  SetPriorityClass
  GlobalMemoryStatusEx
  GetTempPathA
  GetCommandLineW
  GlobalMemoryStatus
  CreateIoCompletionPort
  GetQueuedCompletionStatus
  LocalFree
  GlobalLock
  GlobalUnlock
  GlobalAlloc
  GlobalFree
  GetFullPathNameA
  GetDriveTypeA
  CancelIo
  GetOverlappedResult
  ReadFileEx
  WriteFileEx
  WaitForMultipleObjectsEx
  TerminateThread
  UnmapViewOfFile
  OpenEventA
  OpenFileMappingA
  CreateFileMappingA
  MapViewOfFile
  DeviceIoControl
  OpenFile
  FileTimeToLocalFileTime
  MulDiv
  GetDateFormatA
[OPENGL32.DLL]
  glGetIntegerv
  glGetFloatv
  glGetError
  glGenTextures
  glTexImage2D
  glTexParameteri
  glReadPixels
  wglGetProcAddress
  wglCreateContext
  wglMakeCurrent
  wglDeleteContext
  wglGetCurrentContext
  glGetString
  glCopyTexImage2D
  glCopyTexSubImage2D
  wglGetCurrentDC
  glDepthMask
  glColorMask
  glDisable
  glEnable
  glTexGeni
  glTexEnvi
  glTexEnvf
  glTexEnvfv
  glEnableClientState
  glDisableClientState
  glPolygonOffset
  glMatrixMode
  glBlendFunc
  glCullFace
  glViewport
  glDepthRange
  glPolygonMode
  glClipPlane
  glScissor
  glVertexPointer
  glNormalPointer
  glColorPointer
  glTexCoordPointer
  glLightModelfv
  glLightfv
  glLightf
  glColor4fv
  glMaterialfv
  glLoadMatrixf
  glLoadIdentity
  glTexGenfv
  glLightModeli
  glColorMaterial
  glPixelStorei
  glFogi
  glFogf
  glMaterialf
  glAlphaFunc
  glFogfv
  glDepthFunc
  glFrontFace
  glPointSize
  glBindTexture
  glDeleteTextures
  glTexSubImage2D
  glClearColor
  glClear
  glFinish
  wglSwapLayerBuffers
  glDrawElements
  glDrawArrays
  glLineWidth
  glTexEnviv
  glHint
[VERSION.DLL]
  VerQueryValueA
  GetFileVersionInfoA
  GetFileVersionInfoSizeA
[IMM32.DLL]
  ImmReleaseContext
  ImmGetConversionStatus
  ImmGetContext
  ImmGetCompositionStringA
  ImmAssociateContext
  ImmSetConversionStatus
  ImmAssociateContextEx
  ImmNotifyIME
  ImmGetCandidateListA
[WININET.DLL]
  HttpQueryInfoA
  InternetCloseHandle
  InternetReadFileExA
  InternetConnectA
  InternetSetOptionA
  InternetOpenA
  InternetSetStatusCallbackA
  InternetCrackUrlA
  HttpOpenRequestA
  InternetSetCookieA
  HttpSendRequestA
  InternetSetStatusCallback
[WS2_32.DLL]
  Ordinal_116
  Ordinal_1
  Ordinal_10
  Ordinal_18
  Ordinal_111
  Ordinal_115
  Ordinal_23
  Ordinal_3
  Ordinal_151
  Ordinal_4
  Ordinal_13
  Ordinal_2
  Ordinal_9
  Ordinal_8
  Ordinal_15
  Ordinal_16
  Ordinal_19
  Ordinal_11
  Ordinal_108
  Ordinal_103
  Ordinal_5
  Ordinal_6
  Ordinal_7
  Ordinal_52
  WSACloseEvent
  WSACreateEvent
  Ordinal_21
  WSAEventSelect
  WSAEnumNetworkEvents
  Ordinal_12
  Ordinal_20
  Ordinal_17
[DINPUT8.DLL]
  DirectInput8Create
[USER32.DLL]
  KillTimer
  WaitForInputIdle
  SetTimer
  MsgWaitForMultipleObjects
  MonitorFromPoint
  GetMonitorInfoA
  EnumDisplayDevicesA
  EnumDisplaySettingsA
  RegisterClassExA
  CreateWindowExA
  GetDC
  ReleaseDC
  DestroyWindow
  UnregisterClassA
  ShowWindow
  ChangeDisplaySettingsExA
  SetWindowPos
  GetWindowRect
  ClipCursor
  AdjustWindowRectEx
  GetSystemMetrics
  BeginPaint
  EndPaint
  DefWindowProcA
  MapWindowPoints
  LoadImageA
  LoadCursorA
  GetCursorPos
  ScreenToClient
  GetClientRect
  SetCursor
  LoadStringA
  IsWindow
  IsWindowVisible
  MessageBoxA
  wsprintfA
  LoadBitmapA
  MapVirtualKeyA
  VkKeyScanA
  ClientToScreen
  GetAsyncKeyState
  SystemParametersInfoA
  SendInput
  SetCapture
  ReleaseCapture
  MoveWindow
  SendMessageA
  SetFocus
  GetWindowPlacement
  IsZoomed
  PostQuitMessage
  IsIconic
  PeekMessageA
  GetMessageA
  TranslateMessage
  DispatchMessageA
  GetActiveWindow
  GetKeyState
  MessageBeep
  GetForegroundWindow
  IsDialogMessageA
  GetParent
  TranslateAcceleratorA
  GetKeyboardLayout
  OpenClipboard
  CloseClipboard
  EmptyClipboard
  SetClipboardData
  PostMessageA
  GetDesktopWindow
  CharLowerBuffA
  DrawTextExA
  InvertRect
  FillRect
[GDI32.DLL]
  DescribePixelFormat
  SetPixelFormat
  SetDeviceGammaRamp
  GetPixelFormat
  GetDeviceGammaRamp
  ChoosePixelFormat
  CreateBitmap
  TranslateCharsetInfo
  CreateCompatibleDC
  SelectObject
  BitBlt
  StretchBlt
  DeleteDC
  CreateSolidBrush
  Rectangle
  DeleteObject
  CreateRectRgn
  SelectClipRgn
  SetViewportOrgEx
  OffsetViewportOrgEx
  CreateFontIndirectA
  GetObjectA
  SetMapMode
  SetBkMode
  GetStockObject
  SetBkColor
  SetTextColor
  GdiFlush
  CreateDIBSection
[ADVAPI32.DLL]
  ConvertStringSecurityDescriptorToSecurityDescriptorW
  RegOpenKeyExA
  RegQueryValueExA
  RegCloseKey
  RegCreateKeyExA
  RegSetValueExA
  RegFlushKey
  GetUserNameA
  CryptAcquireContextA
  CryptGenRandom
  CryptReleaseContext
  RegOpenKeyA
  RegEnumKeyA
[SHELL32.DLL]
  ShellExecuteA
  FindExecutableA
[DIVXDECODER.DLL]
  UnInitializeDivxDecoder
  DivxDecode
  InitializeDivxDecoder
  SetOutputFormat
[WINMM.DLL]
  timeGetTime
  waveOutGetNumDevs
  waveInGetNumDevs
  mciSendCommandA
  timeSetEvent
  timeKillEvent
  waveOutOpen
  waveOutClose
  waveOutUnprepareHeader
  waveOutWrite
  waveOutGetPosition
  waveInUnprepareHeader
  waveInPrepareHeader
  waveInAddBuffer
  waveInOpen
  waveInStart
  waveInReset
  waveInClose
  waveOutGetDevCapsA
  waveOutReset
  waveInGetDevCapsA
  waveOutPrepareHeader
[MSACM32.DLL]
  acmStreamSize
  acmStreamOpen
  acmFormatSuggest
  acmStreamUnprepareHeader
  acmStreamConvert
  acmStreamPrepareHeader
[SETUPAPI.DLL]
  SetupDiGetDeviceRegistryPropertyA
  SetupDiGetDeviceInterfaceDetailA
  SetupDiEnumDeviceInterfaces
  SetupDiDestroyDeviceInfoList
  SetupDiEnumDeviceInfo
  SetupDiGetClassDevsA
[HID.DLL]
  HidD_FreePreparsedData
  HidD_GetSerialNumberString
  HidD_GetProductString
  HidP_GetCaps
  HidD_GetAttributes
  HidD_GetPreparsedData
  HidD_SetFeature
  HidD_GetHidGuid
[OLE32.DLL]
  CoInitialize
  PropVariantClear
  CoTaskMemFree
  CoCreateInstance
  CoUninitialize
  CLSIDFromString
```