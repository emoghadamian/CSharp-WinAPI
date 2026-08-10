# PE import-directory inspection

## Scope

This phase parses the normal, on-disk PE Import Directory into `PeImageInfo.Imports`. It is binary-format inspection only: no DLL is loaded, no target process is inspected, and no file is executed or changed.

```text
PE file -> Import Directory -> Imported DLL -> Imported API
```

## Import descriptors and DLL names

The Import Directory data-directory entry points to an array of 20-byte `IMAGE_IMPORT_DESCRIPTOR` values, terminated by an all-zero descriptor. Each descriptor records `OriginalFirstThunk` (Import Lookup Table RVA), `TimeDateStamp`, `ForwarderChain`, `Name` (DLL-name RVA), and `FirstThunk` (IAT RVA). `PeImportModuleInfo` exposes those values, the resolved DLL name, and its functions.

All addresses are RVAs and use the existing `PeImageInfo.GetFileOffsetForRva` conversion. The parser never assumes an RVA equals a file offset. DLL names are bounded, null-terminated ASCII strings.

## Import Lookup Table and IAT

The Import Lookup Table (ILT, also called INT) describes requested symbols. The Import Address Table (IAT) is initially related to that table on disk, but the loader overwrites IAT entries with resolved function addresses when the image is bound or loaded. This library parses the on-disk metadata only; it does not read a process’s live IAT.

If `OriginalFirstThunk` is zero, the parser uses `FirstThunk` as the lookup table, as permitted by normal import layouts. Both lookup-table and IAT RVAs are preserved for each function.

## Import-by-name and import-by-ordinal

An import thunk is 32 bits in PE32 and 64 bits in PE32+. Its high bit selects ordinal import (`bit 31` or `bit 63`) or name import.

- Import-by-name thunks point to `IMAGE_IMPORT_BY_NAME`: a 16-bit hint followed by a null-terminated, case-sensitive ASCII name. The model exposes `Name` and `Hint`.
- Import-by-ordinal thunks expose `Ordinal` and `IsOrdinal`; they intentionally do not invent a name or hint.

## Delay imports

The Delay Import directory is detected through `PeImageInfo.HasDelayImports` but is not parsed as a normal import table and is never merged into `Imports`. Delay-load parsing is deferred because it has a separate descriptor format and loader behavior.

## Defensive validation

PE imports are attacker-controlled metadata. The parser validates import-directory size, descriptor termination, RVA mappings, thunk widths, reserved ordinal bits, hint/name mappings, null terminators, and bounds. It caps descriptors, functions per DLL, and string length; malformed content raises `PeImageInspectionException` with an import-specific validation stage.

## Static-analysis limitations and Blue Team relevance

Imports can support static triage, dependency review, capability inference, family clustering, and detection engineering. APIs such as `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, `WinExec`, networking calls, registry calls, or `OpenProcess` may be interesting in context, but an import only shows that a dependency is available—it does **not** prove execution, intent, or maliciousness.

The PE example caps displayed DLLs and functions so large import tables remain readable and repeats that distinction.

## Microsoft reference

- [PE format: Import Directory, lookup table, hint/name table, and IAT](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
