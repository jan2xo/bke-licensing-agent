using System.Runtime.CompilerServices;

// Narrow permission for Windows source-only crypto/HTTP certification. This is
// not an installed Agent/Launcher IPC extension or a production DI override.
[assembly: InternalsVisibleTo("BKE.LicensingAgent.MachineKeyCertification")]
