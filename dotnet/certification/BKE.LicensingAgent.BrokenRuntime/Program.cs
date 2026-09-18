namespace BKE.LicensingAgent.BrokenRuntime;

internal static class Program
{
    public static int Main()
    {
        Console.Error.WriteLine("BKE Phase 10 certification runtime: intentional startup failure.");
        return 42;
    }
}
