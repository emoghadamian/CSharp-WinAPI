# ETW provider metadata inspection

Event Tracing for Windows (ETW) providers publish event definitions identified by a GUID and usually a registered name. `EtwProviderInspector` reads only the local provider-registration metadata exposed by TDH's `TdhEnumerateProviders`; it does not inspect event payloads or claim to provide a complete event schema.

The laboratory uses a caller-owned managed buffer. TDH first reports the required byte count, then writes `PROVIDER_ENUMERATION_INFO` and its offset-based `TRACE_PROVIDER_INFO` entries into a pinned buffer. Parsing happens while the pin is alive, validates every count and string offset against the returned used length, and copies only GUIDs, names, and raw schema-source values into immutable managed models. No native pointer or pinned buffer escapes the call.

Provider enumeration is bounded to 16,384 entries, a 16 MiB buffer, and 256-character names. It permits only eight size retries when registrations change concurrently. The implementation is architecture-neutral: fixed-width TDH layout fields are decoded explicitly, and no pointer-sized data is exposed. x64 is runtime-tested on this host; x86 and ARM64 are build-validated only.

No trace session is started, no provider is enabled or disabled, no events are collected, and no ETW state is modified. The laboratory does not use tracing, subscription, payload-decoding, kernel, remote, credential, impersonation, privilege, injection, or persistence APIs. Provider metadata does not establish a provider's activity, event contents, authorization, or maliciousness. Event-level metadata and provider fields are deferred because they require separate TDH queries and are outside this focused registration-inspection scope.
