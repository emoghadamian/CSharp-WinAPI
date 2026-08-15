using CSharp.WinAPI.Pipes;
using NamedPipeInspection;
var inspector = new NamedPipeInspector();
var pipes = inspector.EnumerateLocalPipes();
Console.WriteLine($"Local named pipes: {pipes.Count}");
foreach (var pipe in pipes.Take(40)) Console.WriteLine(pipe.Path);
Console.WriteLine($"Raw bounded FindFirstFileW/FindNextFileW example: {RawNamedPipeInspection.Describe()}");
