internal static class ExportManifestBuilder
{
    public static Il2CppExportManifest Build(AnalysisReport report)
    {
        var verifiedByExport = report.ExportMappings.Where(item => item.Present)
            .GroupBy(item => item.Export, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.ToList(), StringComparer.Ordinal);
        var entries = new List<Il2CppExportEntry>();
        foreach (var export in report.GameAssembly.Exports.OrderBy(item => item.Ordinal))
        {
            if (verifiedByExport.TryGetValue(export.Name, out var mappings))
            {
                entries.AddRange(mappings.Select(mapping => new Il2CppExportEntry(mapping.Api, export.Name, export.Ordinal, export.Rva,
                    export.VirtualAddress, "verified", mapping.Evidence, mapping.Confidence)));
            }
            else if (export.Name.StartsWith("il2cpp_", StringComparison.Ordinal))
            {
                entries.Add(new Il2CppExportEntry(export.Name, export.Name, export.Ordinal, export.Rva,
                    export.VirtualAddress, "canonical", "export-name", 1.0));
            }
            else if (IsAlias(export.Name))
            {
                entries.Add(new Il2CppExportEntry(null, export.Name, export.Ordinal, export.Rva,
                    export.VirtualAddress, "unresolved", "alias-candidate", 0.0));
            }
        }
        return new Il2CppExportManifest(
            1,
            report.CreatedAtUtc,
            report.GameAssembly.Sha256,
            report.Profile?.GameVersion,
            report.AutomaticTransform?.SemanticFingerprint,
            entries.Count(item => item.Status is "verified" or "canonical"),
            entries.Count(item => item.Status == "unresolved"),
            entries);
    }

    private static bool IsAlias(string name) => name.Length is >= 8 and <= 24 &&
        name.All(character => char.IsAsciiLetterOrDigit(character) || character == '_');
}

internal sealed record Il2CppExportManifest(int SchemaVersion,
                                            DateTimeOffset CreatedAtUtc,
                                            string GameAssemblySha256,
                                            string? GameVersion,
                                            string? TransformFingerprint,
                                            int ResolvedCount,
                                            int UnresolvedCount,
                                            List<Il2CppExportEntry> Exports);
internal sealed record Il2CppExportEntry(string? Api,
                                         string Export,
                                         long Ordinal,
                                         uint Rva,
                                         ulong VirtualAddress,
                                         string Status,
                                         string Evidence,
                                         double Confidence);
