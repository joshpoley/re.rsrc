# PEB LDR Module Enumeration

Helpers for when reverse engineering code that navigates the `PEB` ➡️ `PEB_LDR_DATA` ➡️ `LDR_DATA_TABLE_ENTRY` transitions.
Since decompiled code will show the relative offsets to the `LIST_ENTRY` field, we can use the below tables
that shows the cooresponding pointer offsets depending on which list we are looking at.

# Shortcuts

For when they extract the n'th module without enumerating the names.

InLoadOrder / InMemoryOrder
1. application exe
2. ntdll.dll
3. kernel32.dll
4. kernelbase.dll

InInitializationOrder
1. ntdll.dll
2. kernelbase.dll
3. kernel32.dll

These modules should all be constant at these spots in the linked list, anything past these are dependent on the process.

# x86 Structures

## x86 In-Load-Order Offsets

>  ( * (int*)(PEB + 0xC) + **0xC** )

```
LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks               : LIST_ENTRY [size:8]
   +0x008 InMemoryOrderLinks             : LIST_ENTRY [size:8]
   +0x010 InInitializationOrderLinks     : LIST_ENTRY [size:8]
   +0x018 DllBase                        : UIntPtr
   +0x01C EntryPoint                     : UIntPtr
   +0x020 SizeOfImage                    : UInt32
   +0x024 FullDllName                    : UNICODE_STRING [size:8]
      +0x024 Length                         : UInt16
      +0x026 MaximumLength                  : UInt16
      +0x028 Buffer                         : IntPtr
   +0x02C BaseDllName                    : UNICODE_STRING [size:8]
      +0x02C Length                         : UInt16
      +0x02E MaximumLength                  : UInt16
      +0x030 Buffer                         : IntPtr
   +0x034 Flags                          : UInt32
   ...
```

## x86 In-Memory-Order Offsets

>  ( * (int*)(PEB + 0xC) + **0x14** )

```
LDR_DATA_TABLE_ENTRY
   -0x008 InLoadOrderLinks               : LIST_ENTRY [size:8]
   +0x000 InMemoryOrderLinks             : LIST_ENTRY [size:8]
   +0x008 InInitializationOrderLinks     : LIST_ENTRY [size:8]
   +0x010 DllBase                        : UIntPtr
   +0x014 EntryPoint                     : UIntPtr
   +0x018 SizeOfImage                    : UInt32
   +0x01C FullDllName                    : UNICODE_STRING [size:8]
      +0x01C Length                         : UInt16
      +0x01E MaximumLength                  : UInt16
      +0x020 Buffer                         : IntPtr
   +0x024 BaseDllName                    : UNICODE_STRING [size:8]
      +0x024 Length                         : UInt16
      +0x026 MaximumLength                  : UInt16
      +0x028 Buffer                         : IntPtr
   +0x02C Flags                          : UInt32
   ...
```

## x86 In-Initialization-Order Offsets

>  ( * (int*)(PEB + 0xC) + **0x1C** )

```
LDR_DATA_TABLE_ENTRY
   -0x010 InLoadOrderLinks               : LIST_ENTRY [size:8]
   -0x008 InMemoryOrderLinks             : LIST_ENTRY [size:8]
   +0x000 InInitializationOrderLinks     : LIST_ENTRY [size:8]
   +0x008 DllBase                        : UIntPtr
   +0x00C EntryPoint                     : UIntPtr
   +0x010 SizeOfImage                    : UInt32
   +0x014 FullDllName                    : UNICODE_STRING [size:8]
      +0x014 Length                         : UInt16
      +0x016 MaximumLength                  : UInt16
      +0x018 Buffer                         : IntPtr
   +0x01C BaseDllName                    : UNICODE_STRING [size:8]
      +0x01C Length                         : UInt16
      +0x01E MaximumLength                  : UInt16
      +0x020 Buffer                         : IntPtr
   +0x024 Flags                          : UInt32
   ...
```

<p/>

# x64 Structures

## x64 In-Load-Order Offsets

>  ( * (int*)(PEB + 0xC) + **0x10** )

```
LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks               : LIST_ENTRY [pack:8 size:16]
   +0x010 InMemoryOrderLinks             : LIST_ENTRY [pack:8 size:16]
   +0x020 InInitializationOrderLinks     : LIST_ENTRY [pack:8 size:16]
   +0x030 DllBase                        : UIntPtr
   +0x038 EntryPoint                     : UIntPtr
   +0x040 SizeOfImage                    : UInt32
   +0x048 FullDllName                    : UNICODE_STRING [pack:8 size:16]
      +0x048 Length                         : UInt16
      +0x04A MaximumLength                  : UInt16
      +0x050 Buffer                         : IntPtr
   +0x058 BaseDllName                    : UNICODE_STRING [pack:8 size:16]
      +0x058 Length                         : UInt16
      +0x05A MaximumLength                  : UInt16
      +0x060 Buffer                         : IntPtr
   +0x068 Flags                          : UInt32
```

## x64 In-Memory-Order Offsets

>  ( * (int*)(PEB + 0xC) + **0x20** )

```
LDR_DATA_TABLE_ENTRY
   -0x010 InLoadOrderLinks               : LIST_ENTRY [pack:8 size:16]
   +0x000 InMemoryOrderLinks             : LIST_ENTRY [pack:8 size:16]
   +0x010 InInitializationOrderLinks     : LIST_ENTRY [pack:8 size:16]
   +0x020 DllBase                        : UIntPtr
   +0x028 EntryPoint                     : UIntPtr
   +0x030 SizeOfImage                    : UInt32
   +0x038 FullDllName                    : UNICODE_STRING [pack:8 size:16]
      +0x038 Length                         : UInt16
      +0x03A MaximumLength                  : UInt16
      +0x040 Buffer                         : IntPtr
   +0x048 BaseDllName                    : UNICODE_STRING [pack:8 size:16]
      +0x048 Length                         : UInt16
      +0x04A MaximumLength                  : UInt16
      +0x050 Buffer                         : IntPtr
   +0x058 Flags                          : UInt32
```

## x64 In-Initialization-Order Offsets

>  ( * (int*)(PEB + 0xC) + **0x30** )

```
LDR_DATA_TABLE_ENTRY
   -0x020 InLoadOrderLinks               : LIST_ENTRY [pack:8 size:16]
   -0x010 InMemoryOrderLinks             : LIST_ENTRY [pack:8 size:16]
   +0x000 InInitializationOrderLinks     : LIST_ENTRY [pack:8 size:16]
   +0x010 DllBase                        : UIntPtr
   +0x018 EntryPoint                     : UIntPtr
   +0x020 SizeOfImage                    : UInt32
   +0x028 FullDllName                    : UNICODE_STRING [pack:8 size:16]
      +0x028 Length                         : UInt16
      +0x02A MaximumLength                  : UInt16
      +0x030 Buffer                         : IntPtr
   +0x038 BaseDllName                    : UNICODE_STRING [pack:8 size:16]
      +0x038 Length                         : UInt16
      +0x03A MaximumLength                  : UInt16
      +0x040 Buffer                         : IntPtr
   +0x048 Flags                          : UInt32
```

