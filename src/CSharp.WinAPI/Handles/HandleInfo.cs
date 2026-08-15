#pragma warning disable CS1591
namespace CSharp.WinAPI.Handles;
/// <summary>Read-only metadata for one system handle-table entry; the value is not access to its underlying object.</summary>
public sealed record HandleInfo(uint ProcessId, nuint HandleValue, ushort ObjectTypeIndex, uint GrantedAccess, uint Attributes, ushort CreatorBackTraceIndex);
#pragma warning restore CS1591
