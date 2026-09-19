using System.Buffers.Binary;

internal static class MetadataNormalizer
{
    private const uint StandardMagic = 0xFAB11BAF;
    private const int StandardHeaderSize = 304;

    public static NormalizationResult Normalize(byte[] source)
    {
        if (source.Length < 8)
            return new(false, "unsupported", source, "Metadata is too short.");
        if (ReadUInt32(source, 0) == StandardMagic)
            return new(false, "standard", source, null);

        foreach (var strategy in new Func<byte[], NormalizationResult>[] { Normalize1899, Normalize1886, Normalize1867 })
        {
            try
            {
                var result = strategy(source);
                if (ReadUInt32(result.Data, 0) == StandardMagic)
                    return result;
            }
            catch (Exception exception) when (exception is InvalidDataException or OverflowException or ArgumentException)
            {
            }
        }
        return new(false, "unsupported", source, $"No normalization strategy validated for observed magic 0x{ReadUInt32(source, 0):X8}.");
    }

    private static NormalizationResult Normalize1867(byte[] source)
    {
        const int encryptedHeaderSize = 368;
        EnsureMinimum(source, encryptedHeaderSize);
        var output = (byte[])source.Clone();
        var header = TransformHeader(source, encryptedHeaderSize, index => (byte)((0xDB - index) & 0xFF));
        var passes = new SectionPass[]
        {
            new(76, 56, 152, 76, 54, true, 48),
            new(92, 20, 88, 92, -90, false, 24),
            new(264, 64, 316, 264, 46, true, 8),
            new(36, -40, 140, 36, 106, false, 40),
            new(228, 56, 188, 228, -54, false, 96),
            new(12, 40, 0, 12, 70, true, 16),
            new(68, -44, 336, 68, -102, true, 168)
        };
        ApplyPasses(output, header, passes);

        var normalized = CreateHeader(29);
        foreach (var pass in passes)
            SetSection(normalized, pass.StandardField, ReadInt32(header, pass.OffsetField) + pass.OffsetAdjustment, ReadInt32(header, pass.LengthField));
        SetSection(normalized, 160, ReadInt32(header, 292), ReadInt32(header, 288));
        SetSection(normalized, 176, ReadInt32(header, 168) + 20, ReadInt32(header, 220));
        SetSection(normalized, 88, ReadInt32(header, 180) - 64, ReadInt32(header, 280));
        SetSection(normalized, 32, ReadInt32(header, 100) - 56, ReadInt32(header, 300) + 16);
        ValidateHeader(normalized, output.Length, false);
        normalized.CopyTo(output, 0);
        return new(true, "vrchat-1867-v29", output, null);
    }

    private static NormalizationResult Normalize1886(byte[] source)
    {
        const int encryptedHeaderSize = 368;
        EnsureMinimum(source, encryptedHeaderSize);
        var output = (byte[])source.Clone();
        var header = TransformHeader(source, encryptedHeaderSize, index => (byte)((0x51 - index) & 0xFF));
        var passes = new SectionPass[]
        {
            new(184, -60, 80, 80, 117, true, 168),
            new(8, 28, 192, 192, 117, true, 16),
            new(260, -24, 272, 272, -117, false, 40),
            new(236, -20, 172, 172, -117, false, 96),
            new(200, -28, 212, 212, 117, true, 8),
            new(244, -48, 16, 16, -117, false, 24),
            new(232, 36, 76, 76, 117, true, 48)
        };
        ApplyPasses(output, header, passes);

        var normalized = CreateHeader(29);
        foreach (var pass in passes)
            SetSection(normalized, pass.StandardField, ReadInt32(header, pass.OffsetField) + pass.OffsetAdjustment, ReadInt32(header, pass.LengthField));
        SetSection(normalized, 160, ReadInt32(header, 104) + 28, ReadInt32(header, 240));
        var typeEnd = ReadInt32(normalized, 160) + ReadInt32(normalized, 164);
        SetSection(normalized, 176, typeEnd, ReadInt32(normalized, 168) - typeEnd);
        var parameters = ScanParameters(output, normalized);
        if (parameters.Offset > 0)
            SetSection(normalized, 88, parameters.Offset, parameters.Size);
        var events = ScanEvents(output, normalized);
        if (events.Offset > 0)
            SetSection(normalized, 32, events.Offset, events.Size);
        ValidateHeader(normalized, output.Length, false);
        normalized.CopyTo(output, 0);
        return new(true, "vrchat-1886-v29", output, null);
    }

    private static NormalizationResult Normalize1899(byte[] source)
    {
        const int encryptedHeaderSize = 384;
        EnsureMinimum(source, encryptedHeaderSize);
        var output = (byte[])source.Clone();
        var header = TransformHeader(source, encryptedHeaderSize, index => (byte)((0x29 + index) & 0xFF));
        Apply1899Section(output, header, 144, -28, 340, true);
        Apply1899Section(output, header, 376, -52, 360, true);
        Apply1899Section(output, header, 348, -36, 64, false);
        Apply1899Section(output, header, 236, 52, 212, false);
        Apply1899Section(output, header, 356, -28, 32, false);
        Apply1899Section(output, header, 20, 20, 92, false);
        Apply1899Section(output, header, 336, 60, 12, true);

        var normalized = CreateHeader(31);
        var sections = new (int Offset, int Size)[]
        {
            (384, 441016), (441400, 2003060), (2444460, 8318916), (10763376, 23064),
            (10786440, 950360), (11736800, 12206196), (23942996, 116136), (24059132, 422940),
            (24482072, 460900), (24942972, 149096), (25092068, 4190292), (29282360, 2006400),
            (31288760, 208848), (31497608, 12120), (31509728, 121088), (31630816, 57256),
            (31688072, 64180), (31752252, 1700168), (33452420, 314632), (33767052, 3342944),
            (37109996, 9160), (37119156, 14656), (37133812, 19816), (37153628, 6276),
            (37159904, 1986468), (39146372, 816072), (39962444, 151420), (40113864, 106952),
            (40220816, 0), (40220816, 0), (40220816, 16220)
        };
        for (var index = 0; index < sections.Length; index++)
            SetSection(normalized, 8 + index * 8, sections[index].Offset, sections[index].Size);
        ValidateHeader(normalized, output.Length, true);
        normalized.CopyTo(output, 0);
        return new(true, "vrchat-1899-v31", output, null);
    }

    private static void ApplyPasses(byte[] output, byte[] header, IEnumerable<SectionPass> passes)
    {
        foreach (var pass in passes)
        {
            var offset = checked(ReadInt32(header, pass.OffsetField) + pass.OffsetAdjustment);
            var length = ReadInt32(header, pass.LengthField);
            EnsureSection(output, offset, length);
            var seed = header[pass.SeedField];
            for (var index = 0; index < length; index++)
            {
                var key = pass.SubtractSeed
                    ? (byte)((index - seed + pass.Key) & 0xFF)
                    : (byte)((seed + index + pass.Key) & 0xFF);
                output[offset + index] ^= key;
            }
        }
    }

    private static void Apply1899Section(byte[] output, byte[] header, int offsetField, int adjustment, int lengthField, bool subtractSeed)
    {
        var offset = checked(ReadInt32(header, offsetField) + adjustment);
        var length = ReadInt32(header, lengthField);
        EnsureSection(output, offset, length);
        var seed = header[lengthField];
        for (var index = 0; index < length; index++)
        {
            var key = subtractSeed
                ? (byte)((index - seed + 58) & 0xFF)
                : (byte)((seed + index - 58) & 0xFF);
            output[offset + index] ^= key;
        }
    }

    private static byte[] TransformHeader(byte[] source, int size, Func<int, byte> key)
    {
        var header = source.AsSpan(0, size).ToArray();
        for (var index = 0; index < header.Length; index++)
            header[index] ^= key(index);
        return header;
    }

    private static byte[] CreateHeader(int version)
    {
        var header = new byte[StandardHeaderSize];
        WriteInt32(header, 0, unchecked((int)StandardMagic));
        WriteInt32(header, 4, version);
        return header;
    }

    private static void SetSection(byte[] header, int field, int offset, int size)
    {
        if (field < 8 || field > header.Length - 8 || (field & 7) != 0)
            throw new InvalidDataException("Invalid metadata header field.");
        WriteInt32(header, field, offset);
        WriteInt32(header, field + 4, size);
    }

    private static void ValidateHeader(byte[] header, int fileLength, bool requireOrdered)
    {
        if (ReadUInt32(header, 0) != StandardMagic || ReadInt32(header, 4) is < 24 or > 40)
            throw new InvalidDataException("The normalized metadata header is invalid.");
        var previousOffset = header.Length;
        for (var field = 8; field <= 248; field += 8)
        {
            var offset = ReadInt32(header, field);
            var size = ReadInt32(header, field + 4);
            if (offset == 0 && size == 0)
                continue;
            EnsureSection(fileLength, offset, size);
            if (offset < header.Length || requireOrdered && offset < previousOffset)
                throw new InvalidDataException("The normalized metadata layout is invalid.");
            previousOffset = offset;
        }
    }

    private static (int Offset, int Size) ScanParameters(byte[] data, byte[] header)
    {
        var stringsSize = ReadInt32(header, 28);
        return Scan(data, 12, 1000, position =>
        {
            var name = ReadInt32(data, position);
            var token = ReadUInt32(data, position + 4);
            var type = ReadInt32(data, position + 8);
            return name >= 0 && name < stringsSize && (token & 0xFF000000) == 0x08000000 && type is >= 0 and < 1_000_000;
        });
    }

    private static (int Offset, int Size) ScanEvents(byte[] data, byte[] header)
    {
        var stringsSize = ReadInt32(header, 28);
        return Scan(data, 24, 100, position =>
        {
            var name = ReadInt32(data, position);
            var type = ReadInt32(data, position + 4);
            var add = ReadInt32(data, position + 8);
            var remove = ReadInt32(data, position + 12);
            return name >= 0 && name < stringsSize && type is >= -1 and < 1_000_000 &&
                   (add == -1 || add is >= 0 and < 1_000_000) &&
                   (remove == -1 || remove is >= 0 and < 1_000_000);
        });
    }

    private static (int Offset, int Size) Scan(byte[] data, int stride, int minimum, Func<int, bool> validator)
    {
        var bestStart = 0;
        var bestCount = 0;
        for (var phase = 0; phase < stride; phase += 4)
        {
            var currentStart = 0;
            var currentCount = 0;
            for (var position = StandardHeaderSize + phase; position + stride <= data.Length; position += stride)
            {
                if (!validator(position))
                {
                    currentCount = 0;
                    continue;
                }
                if (currentCount == 0)
                    currentStart = position;
                currentCount++;
                if (currentCount > bestCount)
                    (bestStart, bestCount) = (currentStart, currentCount);
            }
        }
        return bestCount >= minimum ? (bestStart, bestCount * stride) : (0, 0);
    }

    private static void EnsureMinimum(byte[] data, int minimum)
    {
        if (data.Length < minimum)
            throw new InvalidDataException("The protected metadata header is truncated.");
    }

    private static void EnsureSection(byte[] data, int offset, int size) => EnsureSection(data.Length, offset, size);

    private static void EnsureSection(int length, int offset, int size)
    {
        if (offset < 0 || size < 0 || offset > length - size)
            throw new InvalidDataException("A metadata section is outside the file.");
    }

    private static int ReadInt32(byte[] data, int offset)
    {
        if (offset < 0 || offset > data.Length - 4)
            throw new InvalidDataException("A metadata field is outside the header.");
        return BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset, 4));
    }

    private static uint ReadUInt32(byte[] data, int offset) => unchecked((uint)ReadInt32(data, offset));

    private static void WriteInt32(byte[] data, int offset, int value) =>
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(offset, 4), value);

    private sealed record SectionPass(int OffsetField, int OffsetAdjustment, int LengthField, int SeedField, int Key, bool SubtractSeed, int StandardField);
}

internal sealed record NormalizationResult(bool Applied, string Scheme, byte[] Data, string? Error);
