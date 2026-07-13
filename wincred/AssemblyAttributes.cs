#if !NETSTANDARD2_0
using System.Runtime.Versioning;

// P/Invokes target Win32; ns2.0 has no platform to annotate (and no attribute to annotate it with)
[assembly: SupportedOSPlatform("windows")]
#endif
