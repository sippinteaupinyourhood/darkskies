internal static class CrossBuildExportResolver
{
    public static List<ExportMappingResult> Resolve(PortableExecutable image)
    {
        var targets = image.Exports
            .GroupBy(export => image.ResolveThunkTarget(export.Rva))
            .ToDictionary(group => group.Key, group => group.ToList());
        var results = new List<ExportMappingResult>();
        foreach (var fingerprint in ExportFingerprints.All)
        {
            var pattern = MaskedPattern.Parse(fingerprint.Pattern);
            var bodyMatches = new List<uint>();
            foreach (var section in image.Sections.Where(section => section.IsExecutable))
            {
                foreach (var offset in PatternScanner.FindAll(section.Data, pattern, 2))
                {
                    bodyMatches.Add(section.VirtualAddress + (uint)offset);
                    if (bodyMatches.Count > 1)
                        break;
                }
                if (bodyMatches.Count > 1)
                    break;
            }

            if (bodyMatches.Count != 1 || !targets.TryGetValue(bodyMatches[0], out var exports) || exports.Count != 1)
                continue;
            var export = exports[0];
            results.Add(new ExportMappingResult(fingerprint.Api, export.Name, true, export.Rva,
                export.VirtualAddress, "cross-build-body-signature", 0.92));
        }
        return results
            .GroupBy(result => result.Api, StringComparer.Ordinal)
            .Where(group => group.Select(item => item.Export).Distinct(StringComparer.Ordinal).Count() == 1)
            .Select(group => group.First())
            .ToList();
    }
}

internal sealed record ExportFingerprint(string Api, string Pattern);
