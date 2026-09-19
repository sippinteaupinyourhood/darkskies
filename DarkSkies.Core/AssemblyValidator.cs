using Mono.Cecil;

internal static class AssemblyValidator
{
    public static int Validate(string directory)
    {
        directory = Path.GetFullPath(directory);
        if (!Directory.Exists(directory))
        {
            Console.Error.WriteLine($"Assembly directory was not found: {directory}");
            return 2;
        }

        var paths = Directory.EnumerateFiles(directory, "*.dll").OrderBy(path => path).ToList();
        if (paths.Count == 0)
        {
            Console.Error.WriteLine("No assemblies were found.");
            return 2;
        }

        var resolver = new DefaultAssemblyResolver();
        resolver.AddSearchDirectory(directory);
        var parameters = new ReaderParameters { AssemblyResolver = resolver, ReadingMode = ReadingMode.Immediate };
        var failures = new List<string>();
        var typeCount = 0;
        var methodCount = 0;
        foreach (var path in paths)
        {
            try
            {
                using var assembly = AssemblyDefinition.ReadAssembly(path, parameters);
                foreach (var module in assembly.Modules)
                {
                    var types = module.GetTypes().ToList();
                    typeCount += types.Count;
                    methodCount += types.Sum(type => type.Methods.Count);
                    foreach (var duplicate in types.GroupBy(type => type.FullName, StringComparer.Ordinal)
                                                   .Where(group => group.Count() > 1))
                        failures.Add($"{Path.GetFileName(path)}: duplicate type {duplicate.Key}");
                    foreach (var type in types)
                    {
                        foreach (var method in type.Methods)
                        {
                            _ = method.ReturnType.FullName;
                            foreach (var parameter in method.Parameters)
                                _ = parameter.ParameterType.FullName;
                        }
                        foreach (var field in type.Fields)
                            _ = field.FieldType.FullName;
                        foreach (var property in type.Properties)
                            _ = property.PropertyType.FullName;
                    }
                }
            }
            catch (Exception exception)
            {
                failures.Add($"{Path.GetFileName(path)}: {exception.GetType().Name}: {exception.Message}");
            }
        }

        Console.WriteLine($"Assemblies: {paths.Count}");
        Console.WriteLine($"Types: {typeCount}");
        Console.WriteLine($"Methods: {methodCount}");
        Console.WriteLine($"Failures: {failures.Count}");
        foreach (var failure in failures.Take(100))
            Console.WriteLine(failure);
        return failures.Count == 0 ? 0 : 1;
    }
}
