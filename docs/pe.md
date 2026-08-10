# PE image inspection

## What is a PE image?

Portable Executable (PE) is the Windows executable-image format used by EXEs and DLLs. This phase parses an on-disk byte stream into a managed, read-only model; it does not use the Windows loader, execute the file, or modify any bytes.

```text
Process -> Module -> PE image -> Sections -> Virtual memory
```

Those layers relate but are not identical. A PE file is laid out on disk by file offsets and raw section data. After loading, sections are placed in virtual memory according to RVAs, alignment, relocations, and loader decisions.

## Headers and architecture

The parser validates `MZ` at the DOS header and reads `e_lfanew` at file offset `0x3C`. That offset must lead to the `PE\0\0` signature, followed by the 20-byte COFF/IMAGE_FILE_HEADER. `PeImageInfo` exposes the file header’s machine, section count, timestamp, symbols, optional-header size, and characteristics.

The optional-header magic chooses a distinct layout:

- PE32 (`0x10B`) has 32-bit `ImageBase`, stack, and heap fields.
- PE32+ (`0x20B`) has 64-bit equivalents and omits `BaseOfData`.

The inspector recognizes I386 (`0x014C`), AMD64 (`0x8664`), and ARM64 (`0xAA64`) while retaining the exact raw `Machine` value. Unknown machines stay `Unknown`; they are never guessed to be x86 or x64.

Exposed optional-header fields include linker versions, code/data sizes, entry-point RVA, code base, image base, section/file alignment, image/header sizes, subsystem, DLL characteristics, stack/heap sizing, and data-directory count.

## RVA, VA, and file offset

These are different address spaces:

```text
file offset -- section raw-data mapping --> RVA -- ImageBase + RVA --> VA
```

- A **file offset** is a byte position in the stored file.
- An **RVA** is relative to the base of a loaded image.
- A **VA** is the loaded address in a particular process: `VA = ImageBase + RVA` at the preferred base; relocation may change the actual loaded base.

`PeImageInfo.GetFileOffsetForRva` and `TryGetFileOffsetForRva` map header RVAs directly only within `SizeOfHeaders`. Other RVAs map through a section’s `VirtualAddress`, `PointerToRawData`, and `SizeOfRawData`. An RVA in virtual-only section space or outside any raw range fails rather than incorrectly treating RVA as a file offset.

## Sections and data directories

`PeSectionInfo` exposes the full requested section-header metadata and decodes code, initialized/uninitialized data, read, write, and execute characteristics. Writable-and-executable section flags can be worth investigation, but they are not proof of maliciousness.

The data-directory table is represented by `PeDataDirectoryInfo`. Standard Export, Import, Resource, Exception, Certificate, Base Relocation, Debug, TLS, Load Config, and IAT slots are named. Directory contents are intentionally not parsed in this foundational phase. All directory addresses are RVAs except the Certificate Table directory, whose address is a file offset.

Import/export directories support future dependency and symbol investigations. Relocations support rebasing/ASLR, TLS can describe thread-local initialization, and Load Config contains loader/security metadata. Certificate data is not a normal mapped-image RVA and requires separate signature validation work.

## ASLR and DEP/NX

The optional header’s DLL characteristics include `DYNAMIC_BASE` (ASLR support) and `NX_COMPAT` (DEP/NX compatibility). The parser reports raw flags only; it does not decide that their presence or absence is malicious or perform mitigation changes.

## Validation and attacker-controlled input

PE files can be malformed intentionally. The inspector bounds disk reads to 64 MiB, validates every required range before reading, limits sections to the documented loader maximum of 96, verifies optional-header and data-directory bounds, validates raw section ranges, and uses widened arithmetic for offset/range calculations. Failures produce `PeImageInspectionException` with the supplied path, validation stage, and reason rather than leaking low-level parser errors as the primary API.

## Example and Blue Team relevance

`examples/pe/PeInspection` requires a user-supplied EXE or DLL path and displays format, architecture, entry point, image metadata, sections, and present data directories. It never hard-codes a host executable path.

These primitives support architecture identification, section-permission review, unusual section-name investigation, entry-point review, malformed-file detection, and foundations for later import/export and signature analysis. They do not classify files as malware, execute files, perform injection, patch PE headers, alter sections, manual-map images, or process hollow.

## Microsoft reference

- [PE format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
