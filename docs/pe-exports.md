# PE export-directory inspection

## Export directory and managed model

`PeImageInfo.Exports` is a read-only managed representation of `IMAGE_EXPORT_DIRECTORY` and its tables. The parser handles both PE32 and PE32+ because export-directory entries themselves use 32-bit RVAs in either format; no loader, DLL load, or execution is involved.

```text
IMAGE_EXPORT_DIRECTORY
        |
        +-- AddressOfFunctions       -> Export Address Table
        +-- AddressOfNames           -> Export Name Pointer Table
        +-- AddressOfNameOrdinals    -> Export Ordinal Table
```

The model exposes directory metadata, export DLL name, ordinal base, counts, table RVAs, and one `PeExportFunctionInfo` for every Export Address Table entry.

## Tables, names, and ordinals

The Export Address Table has `NumberOfFunctions` entries. A function index `i` maps to the public ordinal:

```text
public ordinal = OrdinalBase + i
```

The Name Pointer and Ordinal tables have `NumberOfNames` paired entries; `NumberOfNames` may be smaller than `NumberOfFunctions`. Each ordinal-table entry is an index into the Export Address Table, not the public ordinal. A function without an associated name is represented as ordinal-only with `Name = null`; no name is fabricated.

Export DLL names, export names, table entries, and forwarder strings use the existing validated RVA-to-file-offset mapper. No code assumes `RVA == file offset`.

## Forwarded exports

An Export Address Table RVA within the export-directory range is a forwarder string rather than executable code. Such entries have `IsForwarded = true`, `ForwarderName` (for example, `NTDLL.SomeFunction`), and no `AddressRva`. This avoids presenting a forwarder string location as a normal function address.

## Imports versus exports

```text
PE image
  +-- Imports -> APIs required by the image
  +-- Exports -> APIs exposed by the image
```

EXEs can export APIs, though DLLs commonly do. Import and export tables are static metadata: an imported API need not run, and an exported API need not be called. The PE example displays capped lists for both directions and makes that distinction explicit.

## Defensive validation and Blue Team relevance

The parser bounds function/name counts, validates table RVAs and ordinal indexes, checks public-ordinal overflow, bounds null-terminated strings, and preserves contextual `PeImageInspectionException` failures. Malformed tables never trigger unbounded scans or allocations.

Export inspection supports DLL capability inventory, API discovery, forwarded-export review, ordinal-only export review, library comparison, static triage, and clustering. Unusual names, forwarders, or ordinal-only entries need context and are not malware verdicts.

## Microsoft reference

- [PE format: export directory and export tables](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
