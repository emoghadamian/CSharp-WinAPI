# Windows Event Log inspection

`EventLogInspector` provides read-only local channel enumeration and bounded XPath queries. It never clears, writes, deletes, enables, disables, exports, forwards, or subscribes to logs.

## Ownership and bounds

Production interop uses `EvtOpenChannelEnum`, `EvtNextChannelPath`, `EvtQuery`, `EvtNext`, `EvtRender`, and `EvtClose`. Enumerator, query, and event handles are internal `SafeEventHandle` instances released only by `EvtClose`. `ERROR_NO_MORE_ITEMS` is normal enumeration completion.

Channel snapshots are limited to 4,096 entries and 32,768 UTF-16 characters per name. Query paths use the same 32,768-character limit; XPath is limited to 16,384 characters. Both reject embedded null characters before marshaling. Queries require an explicit maximum from 1 through 4,096. Rendered XML is capped at 1 MiB; oversized output fails rather than being truncated. EventData extraction is limited to 512 fields, 256-character names, and 16 KiB values.

## XML and security boundary

Rendered XML is retained exactly as `EventLogRecord.Xml`, the authoritative record form. Namespace-aware `XmlReader` parsing prohibits DTDs, external resolution, entity expansion, and oversized documents. Stable `System` metadata and ordered `EventData` values are exposed only when present.

The laboratory is local-only and does not modify logs, security descriptors, tokens, privileges, memory, or processes. Event Subscription, Event Forwarding, Event Publishing, Log Clearing, and Log Modification are not implemented. x64, x86, and ARM64 builds are compile-time validated; runtime behavior requires validation on the matching Windows host.

## References

- [EvtOpenChannelEnum](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtopenchannelenum), [EvtNextChannelPath](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtnextchannelpath), and [EvtClose](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtclose)
- [EvtQuery](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtquery), [EvtNext](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtnext), and [EvtRender](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtrender)
