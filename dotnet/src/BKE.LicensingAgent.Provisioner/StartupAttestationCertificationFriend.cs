using System.Runtime.CompilerServices;

// Test-only access to the one-shot privileged issuer; no runtime IPC.
[assembly: InternalsVisibleTo("BKE.LicensingAgent.MachineKeyCertification")]
