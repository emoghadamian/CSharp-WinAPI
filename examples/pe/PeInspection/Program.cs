using CSharp.WinAPI.Pe;

// C# byte stream -> validated PE structures -> managed PE model. No Win32 loader API is involved.
if (args.Length != 1)
{
    Console.WriteLine("Usage: PeInspection <path-to-exe-or-dll>");
    return;
}

try
{
    var image = new PeImageInspector().Inspect(args[0]);
    Console.WriteLine($"Format: {image.Format}");
    Console.WriteLine($"Machine: 0x{image.Machine:X4} ({image.Architecture})");
    Console.WriteLine($"Sections: {image.NumberOfSections}");
    Console.WriteLine($"Entry point RVA: 0x{image.AddressOfEntryPoint:X8}");
    Console.WriteLine($"Image base: 0x{image.ImageBase:X16}");
    Console.WriteLine($"Image size: 0x{image.SizeOfImage:X8}");
    Console.WriteLine($"Subsystem: {image.Subsystem}; DLL characteristics: 0x{image.DllCharacteristics:X4}");
    Console.WriteLine();
    Console.WriteLine("Name       RVA        Virtual size Raw size   Raw offset Characteristics");

    foreach (var section in image.Sections)
    {
        Console.WriteLine($"{section.Name,-10} 0x{section.VirtualAddress:X8} 0x{section.VirtualSize:X8} 0x{section.SizeOfRawData:X8} 0x{section.PointerToRawData:X8} {section.Characteristics}");
    }

    Console.WriteLine();
    Console.WriteLine("Data directories (address is an RVA except the Certificate Table, which is a file offset):");

    foreach (var directory in image.DataDirectories.Where(directory => directory.IsPresent))
    {
        Console.WriteLine($"{directory.Kind,-22} 0x{directory.Address:X8} size 0x{directory.Size:X8}{(directory.AddressIsFileOffset ? " (file offset)" : string.Empty)}");
    }

    Console.WriteLine();
    Console.WriteLine($"Normal imported DLLs: {image.Imports.Count}");

    foreach (var module in image.Imports.Take(20))
    {
        Console.WriteLine($"  {module.Name} ({module.Functions.Count} imports)");

        foreach (var function in module.Functions.Take(40))
        {
            var displayName = function.IsOrdinal ? $"ordinal #{function.Ordinal}" : function.Name;
            Console.WriteLine($"    {displayName}");
        }

        if (module.Functions.Count > 40)
        {
            Console.WriteLine($"    ... {module.Functions.Count - 40} additional imports not displayed.");
        }
    }

    if (image.Imports.Count > 20)
    {
        Console.WriteLine($"  ... {image.Imports.Count - 20} additional DLLs not displayed.");
    }

    if (image.HasDelayImports)
    {
        Console.WriteLine("Delay-import directory present; delay-load contents are not parsed by this example.");
    }

    Console.WriteLine("Imports are static PE metadata and do not prove these APIs were executed.");

    Console.WriteLine();

    if (image.Exports is null)
    {
        Console.WriteLine("Exports: none");
    }
    else
    {
        var exports = image.Exports;
        Console.WriteLine($"Exports: {exports.Name}; functions {exports.NumberOfFunctions}; named {exports.NumberOfNames}");
        Console.WriteLine($"Ordinal-only: {exports.Functions.Count(function => !function.IsNamed)}; forwarded: {exports.Functions.Count(function => function.IsForwarded)}");

        foreach (var function in exports.Functions.Take(80))
        {
            var displayName = function.Name ?? $"ordinal #{function.Ordinal}";
            var destination = function.IsForwarded ? $" -> {function.ForwarderName}" : string.Empty;
            Console.WriteLine($"  {displayName}{destination}");
        }

        if (exports.Functions.Count > 80)
        {
            Console.WriteLine($"  ... {exports.Functions.Count - 80} additional exports not displayed.");
        }
    }

    Console.WriteLine("Imports are APIs required by an image; exports are APIs it exposes. Both are metadata, not proof of execution.");

    Console.WriteLine();
    Console.WriteLine("Certificate Table:");
    if (image.CertificateTable is null)
    {
        Console.WriteLine("  Present: No");
    }
    else
    {
        Console.WriteLine($"  Present: Yes; Offset: 0x{image.CertificateTable.FileOffset:X8}; Size: 0x{image.CertificateTable.Size:X8}; Entries: {image.CertificateTable.EntryCount}");
        foreach (var entry in image.CertificateTable.Entries.Take(10))
        {
            Console.WriteLine($"  Revision: 0x{entry.Revision:X4}; Type: 0x{entry.CertificateType:X4}; Length: {entry.Length}");
            if (entry.Certificates is not null)
            {
                Console.WriteLine($"    PKCS#7 metadata: certificates {entry.Certificates.Count}; signers {entry.SignerCount}; digest {entry.DigestAlgorithm}");
                foreach (var certificate in entry.Certificates.Take(3))
                {
                    Console.WriteLine($"    Subject: {certificate.Subject}; Issuer: {certificate.Issuer}");
                    Console.WriteLine($"    Serial: {certificate.SerialNumber}; Thumbprint: {certificate.Thumbprint}");
                    Console.WriteLine($"    Signature: {certificate.SignatureAlgorithm}; Public key: {certificate.PublicKeyAlgorithm}; Valid: {certificate.NotBefore:u} - {certificate.NotAfter:u}");
                }
            }
        }
    }
    Console.WriteLine("Certificate metadata and PKCS#7 parsing do not establish signature validity, trust, or file safety.");
}
catch (PeImageInspectionException exception)
{
    Console.Error.WriteLine(exception.Message);
}
