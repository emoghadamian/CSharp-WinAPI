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
}
catch (PeImageInspectionException exception)
{
    Console.Error.WriteLine(exception.Message);
}
