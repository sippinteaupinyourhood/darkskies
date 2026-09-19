using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

return await DarkSkiesApplication.RunAsync(args);

public static class DarkSkiesApplication
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length == 1 && args[0].Equals("self-test", StringComparison.OrdinalIgnoreCase))
            return RunSelfTest();
        if (args.Length == 2 && args[0].Equals("validate-assemblies", StringComparison.OrdinalIgnoreCase))
            return AssemblyValidator.Validate(args[1]);
        if (args.Length == 4 && args[0].Equals("transform", StringComparison.OrdinalIgnoreCase))
            return await TransformOnlyAsync(args[1], args[2], args[3]);
        if (args.Length == 4 && args[0].Equals("disasm", StringComparison.OrdinalIgnoreCase))
        {
            var rva = Convert.ToUInt32(args[2].Replace("0x", "", StringComparison.OrdinalIgnoreCase), 16);
            var size = Convert.ToUInt32(args[3].Replace("0x", "", StringComparison.OrdinalIgnoreCase), 16);
            foreach (var line in NativeTransformScanner.Disassemble(PortableExecutable.Load(args[1]), rva, size))
                Console.WriteLine(line);
            return 0;
        }
        if (args.Length == 4 && args[0].Equals("read-rva", StringComparison.OrdinalIgnoreCase))
        {
            var image = PortableExecutable.Load(args[1]);
            var rva = Convert.ToUInt32(args[2].Replace("0x", "", StringComparison.OrdinalIgnoreCase), 16);
            var size = Convert.ToInt32(args[3].Replace("0x", "", StringComparison.OrdinalIgnoreCase), 16);
            Console.WriteLine(Convert.ToHexString(image.ReadVirtual(image.ImageBase + rva, size)));
            return 0;
        }
        if (args.Length == 4 && args[0].Equals("solve-header", StringComparison.OrdinalIgnoreCase))
        {
            var input = await File.ReadAllBytesAsync(args[1]);
            var solved = MetadataHeaderSolver.Solve(input, int.Parse(args[2]));
            if (!solved.Success || solved.Data == null)
                return Fail(solved.Error ?? "Header reconstruction failed.");
            await File.WriteAllBytesAsync(Path.GetFullPath(args[3]), solved.Data);
            Console.WriteLine(JsonSerializer.Serialize(solved with { Data = null }, JsonOptions));
            return 0;
        }

        if (args.Length == 0 || args.Any(arg => arg is "-h" or "--help"))
        {
            PrintUsage();
            return args.Length == 0 ? 2 : 0;
        }

        var options = CommandLine.Parse(args);
        if (!File.Exists(options.GameAssemblyPath))
            return Fail($"GameAssembly was not found: {options.GameAssemblyPath}");
        if (options.MetadataPath != null && !File.Exists(options.MetadataPath))
            return Fail($"Metadata was not found: {options.MetadataPath}");

        var profileDatabase = options.ProfilePath == null
            ? ProfileDatabase.CreateDefault()
            : await LoadProfilesAsync(options.ProfilePath);
        var analyzer = new Analyzer(profileDatabase);
        var report = await analyzer.AnalyzeAsync(options.GameAssemblyPath, options.MetadataPath, options.NormalizedOutputPath);
        var json = JsonSerializer.Serialize(report, JsonOptions);
        if (options.OutputPath == null)
            Console.WriteLine(json);
        else
        {
            var outputPath = Path.GetFullPath(options.OutputPath);
            Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
            await File.WriteAllTextAsync(outputPath, json, new UTF8Encoding(false));
            Console.WriteLine($"Report: {outputPath}");
        }
        if (options.ExportsOutputPath != null)
        {
            var exportsPath = Path.GetFullPath(options.ExportsOutputPath);
            Directory.CreateDirectory(Path.GetDirectoryName(exportsPath)!);
            var manifest = ExportManifestBuilder.Build(report);
            await File.WriteAllTextAsync(exportsPath, JsonSerializer.Serialize(manifest, JsonOptions), new UTF8Encoding(false));
            Console.WriteLine($"IL2CPP exports: {exportsPath}");
        }

        Console.Error.WriteLine($"GameAssembly SHA-256: {report.GameAssembly.Sha256}");
        Console.Error.WriteLine($"Exports: {report.GameAssembly.Exports.Count}");
        Console.Error.WriteLine($"Profile: {report.Profile?.Name ?? "unknown build"}");
        Console.Error.WriteLine($"Resolved signatures: {report.Signatures.Count(result => result.Status == ResolutionStatus.Resolved)}");
        Console.Error.WriteLine($"Ambiguous signatures: {report.Signatures.Count(result => result.Status == ResolutionStatus.Ambiguous)}");
        Console.Error.WriteLine(report.AutomaticTransform == null
            ? "Automatic metadata transform: not found or ambiguous"
            : $"Automatic metadata transform: {report.AutomaticTransform.Confidence} confidence, {report.AutomaticTransform.SectionPasses.Count} passes, start {report.AutomaticTransform.LogicalStartRva}");
        if (report.Metadata is { NormalizedHeaderValid: false })
            return 5;
        if (report.Signatures.Any(result => result.Status != ResolutionStatus.Resolved) ||
            report.ExportMappings.Any(result => !result.Present))
            return 3;
        return 0;
    }

    private static async Task<ProfileDatabase> LoadProfilesAsync(string path)
    {
        await using var stream = File.OpenRead(path);
        return await JsonSerializer.DeserializeAsync<ProfileDatabase>(stream, JsonOptions)
               ?? throw new InvalidDataException("The profile database is empty.");
    }

    private static int RunSelfTest()
    {
        var data = new byte[] { 0x10, 0x48, 0x8B, 0x35, 0xAA, 0xBB, 0x48, 0x8B, 0x35, 0x11, 0xBB };
        var pattern = MaskedPattern.Parse("48 8B 35 ?? BB");
        var matches = PatternScanner.FindAll(data, pattern);
        if (matches.Count != 2 || matches[0] != 1 || matches[1] != 6)
            return Fail("Masked pattern test failed.");
        if (PatternScanner.FindAll(data, MaskedPattern.Parse("AA BB CC")).Count != 0)
            return Fail("No-match test failed.");
        try
        {
            _ = MaskedPattern.Parse("?? ??");
            return Fail("All-wildcard rejection test failed.");
        }
        catch (FormatException)
        {
        }
        var standardMetadata = new byte[304];
        BinaryPrimitives.WriteUInt32LittleEndian(standardMetadata, 0xFAB11BAF);
        BinaryPrimitives.WriteInt32LittleEndian(standardMetadata.AsSpan(4), 29);
        var standardResult = MetadataNormalizer.Normalize(standardMetadata);
        if (standardResult.Applied || standardResult.Scheme != "standard" || !standardResult.Data.SequenceEqual(standardMetadata))
            return Fail("Standard metadata pass-through test failed.");
        var unknownResult = MetadataNormalizer.Normalize(new byte[304]);
        if (unknownResult.Applied || unknownResult.Scheme != "unsupported")
            return Fail("Unknown metadata rejection test failed.");
        var truncatedProtected = new byte[32];
        BinaryPrimitives.WriteUInt32LittleEndian(truncatedProtected, 0xD8C4096F);
        var truncatedResult = MetadataNormalizer.Normalize(truncatedProtected);
        if (truncatedResult.Applied || truncatedResult.Scheme != "unsupported")
            return Fail("Truncated protected metadata rejection test failed.");

        Console.WriteLine("Self-test passed.");
        return 0;
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        return 1;
    }

    private static async Task<int> TransformOnlyAsync(string gameAssemblyPath, string metadataPath, string outputPath)
    {
        gameAssemblyPath = Path.GetFullPath(gameAssemblyPath);
        metadataPath = Path.GetFullPath(metadataPath);
        outputPath = Path.GetFullPath(outputPath);
        if (!File.Exists(gameAssemblyPath) || !File.Exists(metadataPath))
            return Fail("The GameAssembly or metadata input does not exist.");
        if (outputPath.Equals(metadataPath, StringComparison.OrdinalIgnoreCase) ||
            Path.GetDirectoryName(outputPath)!.Equals(Path.GetDirectoryName(metadataPath)!, StringComparison.OrdinalIgnoreCase))
            return Fail("Transformed metadata must be written outside the source directory.");
        var recipe = NativeTransformScanner.Scan(PortableExecutable.Load(gameAssemblyPath));
        if (recipe == null || !recipe.Confidence.Equals("high", StringComparison.OrdinalIgnoreCase))
            return Fail("A unique high-confidence metadata transform was not found.");
        var transformed = NativeTransformScanner.Apply(await File.ReadAllBytesAsync(metadataPath), recipe);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllBytesAsync(outputPath, transformed.Data);
        Console.WriteLine($"Transformed metadata: {outputPath}");
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            recipe.HeaderTransform,
            recipe.SectionPasses,
            transformed.Ranges
        }, JsonOptions));
        return 0;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("DarkSkies <GameAssembly.dll> [metadata] [--profiles profiles.json] [--out report.json] [--exports-out il2cpp-exports.json] [--normalized-out metadata.dat]");
        Console.WriteLine("DarkSkies self-test");
        Console.WriteLine("DarkSkies validate-assemblies <directory>");
        Console.WriteLine("DarkSkies transform <GameAssembly.dll> <metadata> <transformed-output>");
    }
}

internal sealed record CommandLine(string GameAssemblyPath, string? MetadataPath, string? ProfilePath, string? OutputPath, string? NormalizedOutputPath, string? ExportsOutputPath)
{
    public static CommandLine Parse(string[] args)
    {
        var positional = new List<string>();
        string? profiles = null;
        string? output = null;
        string? normalizedOutput = null;
        string? exportsOutput = null;
        for (var index = 0; index < args.Length; index++)
        {
            switch (args[index])
            {
                case "--profiles" when index + 1 < args.Length:
                    profiles = args[++index];
                    break;
                case "--out" when index + 1 < args.Length:
                    output = args[++index];
                    break;
                case "--normalized-out" when index + 1 < args.Length:
                    normalizedOutput = args[++index];
                    break;
                case "--exports-out" when index + 1 < args.Length:
                    exportsOutput = args[++index];
                    break;
                case var option when option.StartsWith("--", StringComparison.Ordinal):
                    throw new ArgumentException($"Unknown option: {option}");
                default:
                    positional.Add(args[index]);
                    break;
            }
        }

        if (positional.Count is < 1 or > 2)
            throw new ArgumentException("Expected GameAssembly and optional metadata paths.");
        var metadataPath = positional.Count == 2 ? Path.GetFullPath(positional[1]) : null;
        var normalizedPath = normalizedOutput == null ? null : Path.GetFullPath(normalizedOutput);
        if (normalizedPath != null && metadataPath == null)
            throw new ArgumentException("--normalized-out requires a metadata input.");
        if (normalizedPath != null &&
            Path.GetDirectoryName(normalizedPath)!.Equals(Path.GetDirectoryName(metadataPath)!, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Normalized metadata cannot be written beside the source metadata.");
        return new CommandLine(Path.GetFullPath(positional[0]), metadataPath,
                               profiles == null ? null : Path.GetFullPath(profiles), output, normalizedPath,
                               exportsOutput == null ? null : Path.GetFullPath(exportsOutput));
    }
}

internal sealed class Analyzer(ProfileDatabase database)
{
    public async Task<AnalysisReport> AnalyzeAsync(string gameAssemblyPath, string? metadataPath, string? normalizedOutputPath)
    {
        var gameHash = await HashFileAsync(gameAssemblyPath);
        var profile = database.Profiles.SingleOrDefault(candidate =>
            candidate.GameAssemblySha256.Equals(gameHash, StringComparison.OrdinalIgnoreCase));

        var image = PortableExecutable.Load(gameAssemblyPath);
        var automaticTransform = NativeTransformScanner.Scan(image);
        var metadata = metadataPath == null ? null : await AnalyzeMetadataAsync(metadataPath, normalizedOutputPath, automaticTransform);
        var signatures = new List<SignatureResult>();
        foreach (var signature in profile?.Signatures ?? [])
            signatures.Add(ResolveSignature(image, signature));

        var canonicalExports = image.Exports.Where(export => export.Name.StartsWith("il2cpp_", StringComparison.Ordinal)).ToList();
        var candidateAliases = image.Exports.Where(export => IsAliasCandidate(export.Name)).ToList();
        return new AnalysisReport(
            1,
            DateTimeOffset.UtcNow,
            new GameAssemblyReport(gameHash,
                                   new FileInfo(gameAssemblyPath).Length,
                                   image.ImageBase,
                                   image.Machine,
                                   image.Sections.Select(section => section.ToReport()).ToList(),
                                   image.Exports,
                                   canonicalExports.Count,
                                   candidateAliases.Count),
            metadata,
            profile == null ? null : new ProfileMatch(profile.Name, profile.UnityVersion, profile.GameVersion),
            signatures,
            BuildExportMappings(image, profile),
            automaticTransform);
    }

    private static SignatureResult ResolveSignature(PortableExecutable image, SignatureDefinition definition)
    {
        var pattern = MaskedPattern.Parse(definition.Pattern);
        var sections = definition.Section == null
            ? image.Sections.Where(section => section.IsExecutable)
            : image.Sections.Where(section => section.Name.Equals(definition.Section, StringComparison.OrdinalIgnoreCase));
        var matches = new List<ResolvedAddress>();
        foreach (var section in sections)
        {
            foreach (var relativeOffset in PatternScanner.FindAll(section.Data, pattern, definition.MaxMatches + 1))
            {
                var rva = checked(section.VirtualAddress + (uint)relativeOffset + (uint)definition.ResultOffset);
                matches.Add(new ResolvedAddress(section.Name,
                                                checked(section.FileOffset + relativeOffset + definition.ResultOffset),
                                                rva,
                                                image.ImageBase + rva));
                if (matches.Count > definition.MaxMatches)
                    break;
            }
        }

        var status = matches.Count switch
        {
            0 => ResolutionStatus.NotFound,
            1 => ResolutionStatus.Resolved,
            _ => ResolutionStatus.Ambiguous
        };
        return new SignatureResult(definition.Name, status, matches);
    }

    private static List<ExportMappingResult> BuildExportMappings(PortableExecutable image, CompatibilityProfile? profile)
    {
        if (profile == null)
            return CrossBuildExportResolver.Resolve(image);
        var byName = image.Exports.ToDictionary(export => export.Name, StringComparer.Ordinal);
        return profile.ExportMappings.Select(mapping =>
        {
            var found = byName.TryGetValue(mapping.Export, out var export);
            return new ExportMappingResult(mapping.Api, mapping.Export, found, export?.Rva, export?.VirtualAddress,
                "build-profile", found ? 1.0 : 0.0);
        }).ToList();
    }

    private static bool IsAliasCandidate(string name)
    {
        if (name.StartsWith("il2cpp_", StringComparison.Ordinal) || name.Length is < 8 or > 24)
            return false;
        return name.All(character => char.IsAsciiLetterOrDigit(character) || character == '_');
    }

    private static async Task<MetadataReport> AnalyzeMetadataAsync(string path, string? normalizedOutputPath, NativeTransformReport? automaticTransform)
    {
        var source = await File.ReadAllBytesAsync(path);
        var magic = source.Length >= 4 ? BinaryPrimitives.ReadUInt32LittleEndian(source) : 0u;
        NormalizationResult result;
        try
        {
            result = MetadataNormalizer.Normalize(source);
        }
        catch (Exception exception) when (exception is InvalidDataException or OverflowException or ArgumentException)
        {
            result = new NormalizationResult(false, "invalid", source, exception.Message);
        }
        var normalizedMagic = result.Data.Length >= 4 ? BinaryPrimitives.ReadUInt32LittleEndian(result.Data) : 0u;
        int? normalizedVersion = normalizedMagic == 0xFAB11BAF && result.Data.Length >= 8
            ? BinaryPrimitives.ReadInt32LittleEndian(result.Data.AsSpan(4))
            : null;
        NativeTransformValidation? nativeValidation = null;
        if (normalizedMagic != 0xFAB11BAF && automaticTransform != null)
        {
            try
            {
                var transformed = NativeTransformScanner.Apply(source, automaticTransform);
                var solved = MetadataHeaderSolver.Solve(transformed.Data, automaticTransform.HeaderTransform.HeaderSize);
                if (!solved.Success || solved.Data == null)
                    throw new InvalidDataException(solved.Error ?? "Metadata header reconstruction failed.");
                result = new NormalizationResult(true, "profile-free-native-v29", solved.Data, null);
                normalizedMagic = BinaryPrimitives.ReadUInt32LittleEndian(result.Data);
                normalizedVersion = BinaryPrimitives.ReadInt32LittleEndian(result.Data.AsSpan(4));
                nativeValidation = new NativeTransformValidation(true,
                    Convert.ToHexString(SHA256.HashData(result.Data)), transformed.Ranges, null);
            }
            catch (Exception exception) when (exception is InvalidDataException or OverflowException or ArgumentException)
            {
                nativeValidation = new NativeTransformValidation(false, null, [], exception.Message);
            }
        }
        if (normalizedOutputPath != null && normalizedMagic == 0xFAB11BAF)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(normalizedOutputPath)!);
            await File.WriteAllBytesAsync(normalizedOutputPath, result.Data);
        }
        return new MetadataReport(Convert.ToHexString(SHA256.HashData(source)),
                                  source.LongLength,
                                  $"0x{magic:X8}",
                                  magic == 0xFAB11BAF && source.Length >= 8 ? BinaryPrimitives.ReadInt32LittleEndian(source.AsSpan(4)) : null,
                                  magic == 0xFAB11BAF,
                                  result.Applied ? "normalized" : result.Scheme,
                                  result.Scheme,
                                  result.Applied,
                                  Convert.ToHexString(SHA256.HashData(result.Data)),
                                  normalizedVersion,
                                  normalizedMagic == 0xFAB11BAF,
                                  result.Error,
                                  nativeValidation);
    }

    private static async Task<string> HashFileAsync(string path)
    {
        await using var stream = File.OpenRead(path);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream));
    }
}

internal sealed class PortableExecutable
{
    private readonly byte[] data;

    private PortableExecutable(byte[] data, ulong imageBase, string machine, List<PeSection> sections, List<PeExport> exports)
    {
        this.data = data;
        ImageBase = imageBase;
        Machine = machine;
        Sections = sections;
        Exports = exports;
    }

    public ulong ImageBase { get; }
    public string Machine { get; }
    public List<PeSection> Sections { get; }
    public List<PeExport> Exports { get; }
    public ReadOnlyMemory<byte> Data => data;

    public static PortableExecutable Load(string path)
    {
        var data = File.ReadAllBytes(path);
        using var stream = new MemoryStream(data, writable: false);
        using var reader = new PEReader(stream);
        var headers = reader.PEHeaders;
        var peHeader = headers.PEHeader ?? throw new BadImageFormatException("The file has no PE header.");
        var sections = headers.SectionHeaders.Select(header =>
        {
            var offset = header.PointerToRawData;
            var size = Math.Min(header.SizeOfRawData, Math.Max(0, data.Length - offset));
            var bytes = size == 0 ? [] : data.AsSpan(offset, size).ToArray();
            return new PeSection(header.Name,
                                 checked((uint)header.VirtualAddress),
                                 offset,
                                 checked((uint)header.VirtualSize),
                                 header.SectionCharacteristics.HasFlag(SectionCharacteristics.MemExecute),
                                 bytes);
        }).ToList();
        var image = new PortableExecutable(data,
                                           peHeader.ImageBase,
                                           headers.CoffHeader.Machine.ToString(),
                                           sections,
                                           []);
        image.Exports.AddRange(image.ReadExports(peHeader.ExportTableDirectory));
        return image;
    }

    private IEnumerable<PeExport> ReadExports(DirectoryEntry directory)
    {
        if (directory.RelativeVirtualAddress == 0 || directory.Size < 40)
            yield break;
        var exportOffset = RvaToOffset(checked((uint)directory.RelativeVirtualAddress));
        var ordinalBase = ReadUInt32(exportOffset + 16);
        var numberOfFunctions = ReadUInt32(exportOffset + 20);
        var numberOfNames = ReadUInt32(exportOffset + 24);
        var functionsOffset = RvaToOffset(ReadUInt32(exportOffset + 28));
        var namesOffset = RvaToOffset(ReadUInt32(exportOffset + 32));
        var ordinalsOffset = RvaToOffset(ReadUInt32(exportOffset + 36));
        if (numberOfFunctions > 1_000_000 || numberOfNames > 1_000_000)
            throw new BadImageFormatException("The export table contains implausible counts.");

        for (uint index = 0; index < numberOfNames; index++)
        {
            var nameRva = ReadUInt32(checked(namesOffset + (int)(index * 4)));
            var ordinal = ReadUInt16(checked(ordinalsOffset + (int)(index * 2)));
            if (ordinal >= numberOfFunctions)
                continue;
            var functionRva = ReadUInt32(checked(functionsOffset + ordinal * 4));
            var name = ReadAsciiZ(RvaToOffset(nameRva), 512);
            if (name.Length != 0)
                yield return new PeExport(name, checked((long)ordinalBase + ordinal), functionRva, ImageBase + functionRva);
        }
    }

    public int RvaToOffset(uint rva)
    {
        var section = Sections.FirstOrDefault(candidate =>
            rva >= candidate.VirtualAddress && rva < candidate.VirtualAddress + Math.Max(candidate.VirtualSize, (uint)candidate.Data.Length));
        if (section == null)
            throw new BadImageFormatException($"RVA 0x{rva:X} is outside the mapped sections.");
        return checked(section.FileOffset + (int)(rva - section.VirtualAddress));
    }

    public byte[] ReadVirtual(ulong address, int size)
    {
        if (address < ImageBase || address - ImageBase > uint.MaxValue)
            throw new BadImageFormatException("Virtual address is outside the image.");
        var offset = RvaToOffset((uint)(address - ImageBase));
        EnsureRange(offset, size);
        return data.AsSpan(offset, size).ToArray();
    }

    public uint ResolveThunkTarget(uint rva)
    {
        var seen = new HashSet<uint>();
        for (var depth = 0; depth < 8 && seen.Add(rva); depth++)
        {
            int offset;
            try { offset = RvaToOffset(rva); }
            catch (BadImageFormatException) { break; }
            if (offset < 0 || offset + 5 > data.Length || data[offset] != 0xE9)
                break;
            var displacement = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset + 1, 4));
            var target = (long)rva + 5 + displacement;
            if (target < 0x1000 || target > uint.MaxValue)
                break;
            try { _ = RvaToOffset((uint)target); }
            catch (BadImageFormatException) { break; }
            rva = (uint)target;
        }
        return rva;
    }

    private uint ReadUInt32(int offset)
    {
        EnsureRange(offset, 4);
        return BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
    }

    private ushort ReadUInt16(int offset)
    {
        EnsureRange(offset, 2);
        return BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset, 2));
    }

    private string ReadAsciiZ(int offset, int maximumLength)
    {
        EnsureRange(offset, 1);
        var length = 0;
        while (length < maximumLength && offset + length < data.Length && data[offset + length] != 0)
            length++;
        return Encoding.ASCII.GetString(data, offset, length);
    }

    private void EnsureRange(int offset, int size)
    {
        if (offset < 0 || size < 0 || offset > data.Length - size)
            throw new BadImageFormatException("A PE table points outside the file.");
    }
}

internal sealed record PeSection(string Name, uint VirtualAddress, int FileOffset, uint VirtualSize, bool IsExecutable, byte[] Data)
{
    public PeSectionReport ToReport() => new(Name, VirtualAddress, FileOffset, VirtualSize, Data.Length, IsExecutable);
}

internal sealed record MaskedPattern(byte[] Bytes, bool[] Significant)
{
    public static MaskedPattern Parse(string value)
    {
        var tokens = value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0)
            throw new FormatException("A signature cannot be empty.");
        var bytes = new byte[tokens.Length];
        var significant = new bool[tokens.Length];
        for (var index = 0; index < tokens.Length; index++)
        {
            if (tokens[index] is "?" or "??")
                continue;
            bytes[index] = Convert.ToByte(tokens[index], 16);
            significant[index] = true;
        }
        if (!significant.Any(value => value))
            throw new FormatException("A signature cannot contain only wildcards.");
        return new MaskedPattern(bytes, significant);
    }
}

internal static class PatternScanner
{
    public static List<int> FindAll(ReadOnlySpan<byte> data, MaskedPattern pattern, int limit = int.MaxValue)
    {
        var matches = new List<int>();
        if (pattern.Bytes.Length > data.Length || limit <= 0)
            return matches;
        var anchor = Array.FindIndex(pattern.Significant, value => value);
        for (var offset = 0; offset <= data.Length - pattern.Bytes.Length; offset++)
        {
            if (data[offset + anchor] != pattern.Bytes[anchor])
                continue;
            var matched = true;
            for (var index = 0; index < pattern.Bytes.Length; index++)
            {
                if (pattern.Significant[index] && data[offset + index] != pattern.Bytes[index])
                {
                    matched = false;
                    break;
                }
            }
            if (!matched)
                continue;
            matches.Add(offset);
            if (matches.Count >= limit)
                break;
        }
        return matches;
    }
}

internal sealed record ProfileDatabase(int SchemaVersion, List<CompatibilityProfile> Profiles)
{
    public static ProfileDatabase CreateDefault() => new(1,
    [
        new("VRChat 2026.2.3p3 build 1867", "2022.3.22f2", "2026.2.3p3-1867", "75AAB99E12ED683613BB2C2B1035BFF164BB8FADFC0A148C770FAA206DDCB7CB", [], []),
        new("VRChat build 1886", "2022.3.22f2", "2026.3.1-1886", "46856D668C1B93EDAC76C34A297460C5D0A3A0698B766F2A34F3C3DDB0517E94", [], KnownExportMaps.Build1886()),
        new("VRChat Unity 6 build 1899", "6000.0.67f1", "2026.3.2-1899", "CCDCBA4CE64C74F9C406E1D43AD93E373A6240CD8EB8A1BFE162CA6019B12C22", [],
        [
            new("il2cpp_object_get_virtual_method", "bdetPLUGbMl"),
            new("il2cpp_object_new", "fdQySFUbQRI"),
            new("il2cpp_value_box", "kfRjLqgoDfp"),
            new("il2cpp_class_get_methods", "nVnxgXSkJqb"),
            new("il2cpp_class_get_field_from_name", "FZOoKkQcXXF"),
            new("il2cpp_class_from_name", "eGcVXosuX_V"),
            new("il2cpp_class_from_il2cpp_type", "oQbALanOaVu"),
            new("il2cpp_runtime_class_init", "zoAvzVWlTDk"),
            new("il2cpp_runtime_invoke", "UPSmEOKKvNa"),
            new("il2cpp_gchandle_new", "KUZulelZoCy"),
            new("il2cpp_gchandle_new_weakref", "MHaleuaBdai"),
            new("il2cpp_array_new", "TRPYdGIRWWf"),
            new("il2cpp_image_get_class", "VyIwDMHEORj"),
            new("il2cpp_field_static_get_value", "XTRIwAekovu"),
            new("il2cpp_field_static_set_value", "IEmYkLTqwJX")
        ])
    ]);
}

internal sealed record CompatibilityProfile(string Name,
                                            string UnityVersion,
                                            string GameVersion,
                                            string GameAssemblySha256,
                                            List<SignatureDefinition> Signatures,
                                            List<ExportMapping> ExportMappings);
internal sealed record SignatureDefinition(string Name, string Pattern, string? Section = ".text", int ResultOffset = 0, int MaxMatches = 1);
internal sealed record ExportMapping(string Api, string Export);
internal sealed record AnalysisReport(int SchemaVersion,
                                      DateTimeOffset CreatedAtUtc,
                                      GameAssemblyReport GameAssembly,
                                      MetadataReport? Metadata,
                                      ProfileMatch? Profile,
                                      List<SignatureResult> Signatures,
                                      List<ExportMappingResult> ExportMappings,
                                      NativeTransformReport? AutomaticTransform);
internal sealed record GameAssemblyReport(string Sha256,
                                          long Size,
                                          ulong ImageBase,
                                          string Machine,
                                          List<PeSectionReport> Sections,
                                          List<PeExport> Exports,
                                          int CanonicalIl2CppExportCount,
                                          int CandidateAliasCount);
internal sealed record MetadataReport(string Sha256,
                                      long Size,
                                      string Magic,
                                      int? Version,
                                      bool StandardHeader,
                                      string Status,
                                      string NormalizationScheme,
                                      bool NormalizationApplied,
                                      string NormalizedSha256,
                                      int? NormalizedVersion,
                                      bool NormalizedHeaderValid,
                                      string? NormalizationError,
                                      NativeTransformValidation? AutomaticTransformValidation);
internal sealed record NativeTransformValidation(bool Applied,
                                                  string? TransformedSha256,
                                                  List<NativeTransformRange> Ranges,
                                                  string? Error);
internal sealed record ProfileMatch(string Name, string UnityVersion, string GameVersion);
internal sealed record PeSectionReport(string Name, uint Rva, int FileOffset, uint VirtualSize, int RawSize, bool Executable);
internal sealed record PeExport(string Name, long Ordinal, uint Rva, ulong VirtualAddress);
internal sealed record SignatureResult(string Name, ResolutionStatus Status, List<ResolvedAddress> Matches);
internal sealed record ResolvedAddress(string Section, int FileOffset, uint Rva, ulong VirtualAddress);
internal sealed record ExportMappingResult(string Api, string Export, bool Present, uint? Rva, ulong? VirtualAddress,
                                           string Evidence = "build-profile", double Confidence = 1.0);
internal enum ResolutionStatus { NotFound, Resolved, Ambiguous }
