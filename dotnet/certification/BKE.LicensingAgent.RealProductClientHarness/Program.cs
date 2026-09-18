using System.Reflection;
using System.Runtime.Loader;

if (args.Length != 4)
{
    Console.Error.WriteLine("usage: harness <product-assembly> <agent-client-type> <method> <expected-status>");
    return 2;
}

var assemblyPath = Path.GetFullPath(args[0]);
var productDirectory = Path.GetDirectoryName(assemblyPath)
    ?? throw new InvalidOperationException("Product assembly directory is unavailable.");

AssemblyLoadContext.Default.Resolving += (_, name) =>
{
    var candidate = Path.Combine(productDirectory, name.Name + ".dll");
    return File.Exists(candidate) ? AssemblyLoadContext.Default.LoadFromAssemblyPath(candidate) : null;
};

var assembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(assemblyPath);
var clientType = assembly.GetType(args[1], throwOnError: true)
    ?? throw new InvalidOperationException("Agent client type is unavailable.");
var method = clientType.GetMethod(
    args[2],
    BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
    ?? throw new MissingMethodException(clientType.FullName, args[2]);

var instance = Activator.CreateInstance(clientType, nonPublic: true)
    ?? throw new InvalidOperationException("Agent client could not be constructed.");

try
{
    var invocation = method.Invoke(instance, new object?[] { CancellationToken.None })
        ?? throw new InvalidOperationException("Agent client returned no task.");
    if (invocation is not Task task)
        throw new InvalidOperationException("Agent client method did not return a Task.");

    await task.ConfigureAwait(false);

    var resultProperty = task.GetType().GetProperty("Result")
        ?? throw new InvalidOperationException("Agent client task returned no result.");
    var result = resultProperty.GetValue(task)
        ?? throw new InvalidOperationException("Agent client returned a null result.");
    var statusProperty = result.GetType().GetProperty(
        "Status",
        BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("Agent client result has no status.");
    var status = statusProperty.GetValue(result)?.ToString() ?? string.Empty;

    Console.WriteLine($"{clientType.FullName}.{method.Name} => {status}");
    if (!string.Equals(status, args[3], StringComparison.Ordinal))
    {
        Console.Error.WriteLine($"Expected status {args[3]}, got {status}.");
        return 1;
    }

    return 0;
}
finally
{
    if (instance is IDisposable disposable)
        disposable.Dispose();
}
