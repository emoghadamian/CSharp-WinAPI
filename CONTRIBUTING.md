# Contributing

CSharp-WinAPI is a Windows-native, read-only learning and inspection laboratory. Develop on Windows with the .NET 8 SDK; Visual Studio and VS Code are optional editors.

Before opening a pull request, run:

```powershell
dotnet restore CSharp-WinAPI.sln
dotnet build CSharp-WinAPI.sln --configuration Debug
dotnet run --project tests/CSharp.WinAPI.Tests/CSharp.WinAPI.Tests.csproj --configuration Debug
```

Run every affected example under `examples/` as well. Preserve the existing layering: native interop and resource ownership stay internal, public models remain immutable managed snapshots, and every native allocation or handle uses its documented cleanup path.

Use `LibraryImport` for production interop, keep raw structures and SafeHandles internal, and add bounded parser fixtures plus lifecycle tests for native-boundary changes. Keep the project read-only: do not add mutation, impersonation, privilege, credential, injection, persistence, or remote-control capabilities without an explicitly approved scope change.

Do not commit `bin/`, `obj/`, IDE files, certificates, private keys, secrets, or machine-specific artifacts. Use focused Conventional Commit-style messages and include related tests, examples, and documentation in the same change.
