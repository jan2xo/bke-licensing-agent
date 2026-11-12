using System.Runtime.CompilerServices;

// Test-only friend. No production runtime/IPC/client receives the alternate
// binding or signer seam. The production constructor enforces Windows DPAPI.
[assembly: InternalsVisibleTo("BKE.LicensingAgent.DsHttpCertification")]
[assembly: InternalsVisibleTo("BKE.LicensingAgent.ContractCertification")]
