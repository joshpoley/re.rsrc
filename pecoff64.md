# Distilled PECoff (x64)

This document takes relevant details from the [pecoff (exe/dll) specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), designed to make it easy to lookup fields when reverse engineering code that manually walks exe/dll data structures.

This is the version for **64-bit binaries**, the [32-bit version is here](pecoff32.md).

### Example

Given the below decompiled C code, we want to figure out the name/types for `pbVar6`, `uVar1`, and `uVar2`.

```cpp
pe_offset = *(int *)(image_base + 0x3c);
pbVar6 = image_base + *(uint *)(image_base + (longlong)pe_offset + 0x88);
uVar1 = *(uint *)(pbVar6 + 0x24);
uVar2 = *(uint *)(pbVar6 + 0x20);
```

1. `image_base + 0x3C` contains the PE header offset (aka e_lfanew)
2. With the lookup below, an offset of `0x88` from the start of the PE header, gives us the Export Directory offset.
3. `uVar1` and `uVar2` can automatically be resolved once we apply the appropriate type to `pbVar6`:

```cpp
pe_offset = *(int *)(image_base + 0x3c);
export_dir = (IMAGE_EXPORT_DIRECTORY *)(image_base + *(uint *)(image_base + (longlong)pe_offset + 0x88));
uVar1 = export_dir->AddressOfNameOrdinals;
uVar2 = export_dir->AddressOfNames;
```

<p/>

## Magic Values

Spotting these in the decompiled code will certainly hint at PECoff walking code:

| Value | Description |
| --- | --- |
| 0x3C | Offset to e_lfanew (PE offset) |
| 0x5A4D | "MZ" |
| 0x4550 | "PE" |
| 0x014c | i386 Machine type |
| 0x8664 | x64 Machine type |
| 0x010B | 32-bit optional header magic |
| 0x020B | 64-bit optional header magic |

<p/>

## MZ Headers

**Location: Offset 0x0**

```cpp
IMAGE_DOS_HEADER
+0x000                                : IMAGE_DOS_HEADER [pack:4 size:64]
    +0x000 e_magic                        : Char[2]    // "MZ" or 0x5a4d
    +0x002 e_cblp                         : UInt16
    +0x004 e_cp                           : UInt16
    +0x006 e_crlc                         : UInt16
    +0x008 e_cparhdr                      : UInt16
    +0x00A e_minalloc                     : UInt16
    +0x00C e_maxalloc                     : UInt16
    +0x00E e_ss                           : UInt16
    +0x010 e_sp                           : UInt16
    +0x012 e_csum                         : UInt16
    +0x014 e_ip                           : UInt16
    +0x016 e_cs                           : UInt16
    +0x018 e_lfarlc                       : UInt16
    +0x01A e_ovno                         : UInt16
    +0x01C e_res                          : UInt16[4]
    +0x024 e_oemid                        : UInt16
    +0x026 e_oeminfo                      : UInt16
    +0x028 e_res2                         : UInt16[10]
    +0x03C e_lfanew                       : Int32      // PE Header offset
```

<p/>

## Extra metadata

**Location: Offset 0x40**

16-bit DOS code, "Rich" compiler versions, empty padding.

<p/>

## PE Header & Optional Header

**Location: Offset stored in IMAGE_DOS_HEADER + 0x3C**

```cpp
IMAGE_NT_HEADERS64
+0x000                                : IMAGE_NT_HEADERS64 [pack:4 size:264]
   +0x000 Signature                      : UInt32                 // "PE\0\0" or 0x4550
   +0x004 FileHeader                     : IMAGE_FILE_HEADER [pack:4 size:20]
      +0x004 Machine                        : MACHINE_TYPE        // 0x8664=x64
      +0x006 NumberOfSections               : UInt16
      +0x008 TimeDateStamp                  : UInt32
      +0x00C PointerToSymbolTable           : UInt32
      +0x010 NumberOfSymbols                : UInt32
      +0x014 SizeOfOptionalHeader           : UInt16
      +0x016 Characteristics                : IMAGE_CHARACTERISTICS
   +0x018 OptionalHeader                 : IMAGE_OPTIONAL_HEADER64 [pack:4 size:240]
      +0x018 Magic                          : IMAGE_OPTIONAL_TYPE // 0x020B=64bit
      +0x01A MajorLinkerVersion             : Byte
      +0x01B MinorLinkerVersion             : Byte
      +0x01C SizeOfCode                     : UInt32
      +0x020 SizeOfInitializedData          : UInt32
      +0x024 SizeOfUninitializedData        : UInt32
      +0x028 AddressOfEntryPoint            : UInt32
      +0x02C BaseOfCode                     : UInt32
      +0x030 ImageBase                      : UInt64
      +0x038 SectionAlignment               : UInt32
      +0x03C FileAlignment                  : UInt32
      +0x040 MajorOperatingSystemVersion    : UInt16
      +0x042 MinorOperatingSystemVersion    : UInt16
      +0x044 MajorImageVersion              : UInt16
      +0x046 MinorImageVersion              : UInt16
      +0x048 MajorSubsystemVersion          : UInt16
      +0x04A MinorSubsystemVersion          : UInt16
      +0x04C Win32VersionValue              : UInt32
      +0x050 SizeOfImage                    : UInt32
      +0x054 SizeOfHeaders                  : UInt32
      +0x058 CheckSum                       : UInt32
      +0x05C Subsystem                      : IMAGE_SUBSYSTEM
      +0x05E DllCharacteristics             : IMAGE_DLL_CHARACTERISTICS
      +0x060 SizeOfStackReserve             : UInt64
      +0x068 SizeOfStackCommit              : UInt64
      +0x070 SizeOfHeapReserve              : UInt64
      +0x078 SizeOfHeapCommit               : UInt64
      +0x080 LoaderFlags                    : UInt32
      +0x084 NumberOfRvaAndSizes            : UInt32
      +0x088 DataDirectory                  : IMAGE_DATA_DIRECTORY[16]
         +0x088 Export Directory               : IMAGE_EXPORT_DIRECTORY*
         +0x090 Import Directory               : IMAGE_IMPORT_DESCRIPTOR*
         +0x098 Resource Directory             : IMAGE_RESOURCE_DIRECTORY*
         +0x0A0 Exception Directory            : 
         +0x0A8 Security Directory             : Certificates
         +0x0B0 Base Relocation Table          : 
         +0x0B8 Debug Directory                : IMAGE_DEBUG_DIRECTORY*
         +0x0C0 Architecture (reserved)        : 
         +0x0C8 Global Pointer value           : 
         +0x0D0 TLS Directory                  : IMAGE_TLS_DIRECTORY64*
         +0x0D8 Load Configuration             : IMAGE_LOAD_CONFIG_DIRECTORY64*
         +0x0E0 Bound Import Dir               : 
         +0x0E8 Import Address Table           : 
         +0x0F0 DelayLoad Import Descriptors   : IMAGE_DELAYLOAD_DESCRIPTOR*
         +0x0F8 CLR Runtime Header             : IMAGE_COR20_HEADER*
         +0x100 Reserved                       : 



```

Note that the Size field (from the IMAGE_DATA_DIRECTORY struct) is omitted from the above DataDirectory array:

```cpp
IMAGE_DATA_DIRECTORY
+0x000                                : IMAGE_DATA_DIRECTORY [pack:4 size:8]
   +0x000 VirtualAddress                 : UInt32
   +0x004 Size                           : UInt32
```

<p/>

## Array of Section Headers

**Location: Immediately following OptionalHeader (PE offset + 0x18 + SizeOfOptionalHeader)**

There will be `IMAGE_FILE_HEADER.NumberOfSections` entries in the array.

```cpp
IMAGE_SECTION_HEADER
+0x000                                : IMAGE_SECTION_HEADER [pack:4 size:40]
   +0x000 szName                         : Byte[8]
   +0x008 VirtualSize                    : UInt32
   +0x00C VirtualAddress                 : UInt32
   +0x010 SizeOfRawData                  : UInt32
   +0x014 PointerToRawData               : UInt32
   +0x018 PointerToRelocations           : UInt32
   +0x01C PointerToLinenumbers           : UInt32
   +0x020 NumberOfRelocations            : UInt16
   +0x022 NumberOfLinenumbers            : UInt16
   +0x024 Characteristics                : SECTION_CHARACTERISTICS
```

<p/>

## Export Directory

**Location: DataDirectory[0].VirtualAddress**

```cpp
IMAGE_EXPORT_DIRECTORY
+0x000                                : IMAGE_EXPORT_DIRECTORY [pack:4 size:40]
   +0x000 Characteristics                : UInt32
   +0x004 TimeDateStamp                  : UInt32
   +0x008 MajorVersion                   : UInt16
   +0x00A MinorVersion                   : UInt16
   +0x00C NameRVA                        : UInt32
   +0x010 OrdinalBase                    : UInt32
   +0x014 NumberOfFunctions              : UInt32
   +0x018 NumberOfNames                  : UInt32
   +0x01C AddressOfFunctions             : UInt32
   +0x020 AddressOfNames                 : UInt32
   +0x024 AddressOfNameOrdinals          : UInt32
```

<p/>

## Import Directory

**Location: DataDirectory[1].VirtualAddress**

```cpp
IMAGE_IMPORT_DESCRIPTOR
+0x000                                : IMAGE_IMPORT_DESCRIPTOR [pack:4 size:20]
   +0x000 OriginalFirstThunk             : UInt32
   +0x004 TimeDateStamp                  : UInt32
   +0x008 ForwarderChain                 : UInt32
   +0x00C NameRVA                        : UInt32
   +0x010 FirstThunk                     : UInt32
```
<p/>

## TLS Directory

**Location: DataDirectory[9].VirtualAddress**

```cpp
IMAGE_TLS_DIRECTORY64
+0x000                                : IMAGE_TLS_DIRECTORY64 [pack:4 size:40]
   +0x000 StartAddressOfRawData          : UInt64
   +0x008 EndAddressOfRawData            : UInt64
   +0x010 AddressOfIndex                 : UInt64
   +0x018 AddressOfCallBacks             : UInt64
   +0x020 SizeOfZeroFill                 : UInt32
   +0x024 Characteristics                : TLS_CHARACTERISTICS
```

<p/>

## Delay Load Directory

**Location: DataDirectory[13].VirtualAddress**

```cpp
IMAGE_DELAYLOAD_DESCRIPTOR
+0x000                                : IMAGE_DELAYLOAD_DESCRIPTOR [pack:4 size:32]
   +0x000 Attributes                     : UInt32
   +0x004 DllNameRVA                     : UInt32
   +0x008 ModuleHandleRVA                : UInt32
   +0x00C ImportAddressTableRVA          : UInt32
   +0x010 ImportNameTableRVA             : UInt32
   +0x014 BoundImportAddressTableRVA     : UInt32
   +0x018 UnloadInformationTableRVA      : UInt32
   +0x01C TimeDateStamp                  : UInt32
```
