using System.Buffers.Binary;

internal static class MetadataHeaderSolver
{
    private const uint Magic = 0xFAB11BAF;
    private static readonly int[] RecordStrides =
    [
        8, 1, 1, 24, 20, 32, 12, 12, 1, 12, 12, 12, 16, 4, 16, 4,
        4, 4, 8, 88, 40, 64, 8, 4, 1, 8, 4, 8, 8, 1, 4
    ];

    public static HeaderSolveResult Solve(byte[] transformed, int protectedHeaderSize, int metadataVersion = 29)
    {
        if (metadataVersion != 29)
            return HeaderSolveResult.Failure("Profile-free header reconstruction currently supports metadata v29 only.");
        if (protectedHeaderSize < 256 || protectedHeaderSize > transformed.Length)
            return HeaderSolveResult.Failure("The protected header size is invalid.");
        var values = new List<HeaderValue>();
        for (var field = 0; field <= protectedHeaderSize - 4; field += 4)
        {
            var value = BinaryPrimitives.ReadInt32LittleEndian(transformed.AsSpan(field, 4));
            if (value >= 0 && value <= transformed.Length)
                values.Add(new HeaderValue(field, value));
        }

        var states = new List<SolveState> { new(protectedHeaderSize, [], [], 0) };
        var reachedSection = -1;
        string? terminalDiagnostic = null;
        for (var section = 0; section < RecordStrides.Length && states.Count != 0; section++)
        {
            var nextStates = new List<SolveState>();
            if (section == 24)
            {
                foreach (var state in states)
                foreach (var boundaryValue in values)
                for (var delta = -128; delta <= 128; delta += 4)
                {
                    var rangeBoundary = boundaryValue.Value + delta;
                    if (!LooksLikeAttributeDataRange(transformed, rangeBoundary))
                        continue;
                    for (var gap = 0; gap <= 4; gap++)
                    {
                        var actualSize = rangeBoundary - state.Boundary - gap;
                        if (actualSize <= 0)
                            continue;
                        AddState(nextStates, state, new HeaderValue(-1, actualSize), actualSize,
                            rangeBoundary, Math.Abs(delta) + Math.Abs(gap - 1) * 8 + 8, boundaryValue);
                    }
                }
            }
            else if (section == 9)
            {
                foreach (var state in states)
                foreach (var boundaryValue in values)
                for (var delta = -128; delta <= 128; delta += 4)
                {
                    var parameterBoundary = boundaryValue.Value + delta;
                    if (!LooksLikeParameterTable(transformed, parameterBoundary))
                        continue;
                    for (var gap = 0; gap <= 16; gap += 4)
                    {
                        var actualSize = parameterBoundary - state.Boundary - gap;
                        if (actualSize <= 0 || actualSize % RecordStrides[section] != 0)
                            continue;
                        AddState(nextStates, state, new HeaderValue(-1, actualSize), actualSize,
                            parameterBoundary, Math.Abs(delta) + gap + 8, boundaryValue);
                    }
                }
            }
            else if (section == 28)
            {
                foreach (var state in states)
                for (var inferredSize = 24; inferredSize <= 24; inferredSize += 8)
                {
                    var end = state.Boundary + inferredSize;
                    if (end >= transformed.Length)
                        continue;
                    var distance = values.Min(item => Math.Abs((long)item.Value - end));
                    if (distance > 128)
                        continue;
                    var sizeDistance = values.Min(item => Math.Abs((long)item.Value - inferredSize));
                    AddState(nextStates, state, new HeaderValue(-1, inferredSize), inferredSize, end,
                        checked((int)(distance + sizeDistance)) + 32);
                }
            }
            else if (section == RecordStrides.Length - 2)
            {
                foreach (var state in states)
                foreach (var exportedValue in values)
                foreach (var adjustment in Adjustments(4))
                {
                    if (state.UsedFields.Contains(exportedValue.Field))
                        continue;
                    var exportedSize = exportedValue.Value + adjustment;
                    var inferredSize = transformed.Length - state.Boundary - exportedSize;
                    if (exportedSize <= 0 || exportedSize % 4 != 0 || inferredSize <= 0 || inferredSize > 1_000_000)
                        continue;
                    AddState(nextStates, state, new HeaderValue(-1, inferredSize), inferredSize,
                        state.Boundary + inferredSize, Math.Abs(adjustment) * 4 + 64);
                }
            }
            else
            foreach (var state in states)
            foreach (var sizeValue in values)
            foreach (var adjustment in Adjustments(RecordStrides[section]))
            {
                var actualSize = sizeValue.Value + adjustment;
                if (state.UsedFields.Contains(sizeValue.Field) || actualSize <= 0 ||
                    actualSize % RecordStrides[section] != 0)
                    continue;
                var end = (long)state.Boundary + actualSize;
                if (end > transformed.Length)
                    continue;
                if (section == RecordStrides.Length - 1)
                {
                    var finalGap = transformed.Length - (int)end;
                    if (finalGap is < 0 or > 8)
                        continue;
                    AddState(nextStates, state, sizeValue, actualSize, (int)end + finalGap,
                        finalGap + Math.Abs(adjustment) * 4 +
                        ExportedTypeDefinitionPenalty(transformed, state.Boundary, actualSize));
                    continue;
                }
                var distance = values.Min(item => Math.Abs((long)item.Value - end));
                if (distance > 128)
                    continue;
                AddState(nextStates, state, sizeValue, actualSize, (int)end,
                    checked((int)distance) + Math.Abs(adjustment) * 4);
                if (section == 10)
                {
                    for (var delta = -128; delta <= 128; delta += 4)
                    {
                        var inferredBoundary = (int)end + delta;
                        if (LooksLikeFieldTable(transformed, inferredBoundary))
                            AddState(nextStates, state, sizeValue, actualSize, inferredBoundary,
                                Math.Abs(delta) + Math.Abs(adjustment) * 4 + 8);
                    }
                }
                if (section == 18)
                {
                    for (var delta = -512; delta <= 512; delta += 4)
                    {
                        var inferredBoundary = (int)end + delta;
                        if (LooksLikeTypeDefinitionTable(transformed, inferredBoundary))
                            AddState(nextStates, state, sizeValue, actualSize, inferredBoundary,
                                Math.Abs(delta) + Math.Abs(adjustment) * 4 + 8);
                    }
                }
                if (section == 19)
                {
                    for (var delta = -512; delta <= 512; delta += 4)
                    {
                        var inferredBoundary = (int)end + delta;
                        if (LooksLikeImageTable(transformed, inferredBoundary, 40 * 20))
                            AddState(nextStates, state, sizeValue, actualSize, inferredBoundary,
                                Math.Abs(delta) + Math.Abs(adjustment) * 4 + 8);
                    }
                }
            }
            if (nextStates.Count == 0)
            {
                var bestPrevious = states.OrderBy(state => state.Score).FirstOrDefault();
                var samples = string.Join(",", states.Take(8).Select(state => transformed.Length - state.Boundary));
                terminalDiagnostic = $" stoppedBeforeSection={section}; remainingBytes={samples}" +
                    (bestPrevious == null ? string.Empty :
                        $"; bestPrevious={string.Join(';', bestPrevious.Sections.Select(item => $"{item.Offset}:{item.Size}"))}");
            }
            var filteredStates = nextStates
                .Where(state => ValidatePartialCandidate(transformed, state.Sections, state.Boundary))
                .OrderBy(state => state.Score)
                .Take(2_000)
                .ToList();
            if (filteredStates.Count == 0 && nextStates.Count != 0)
            {
                var orderedBoundaries = nextStates.Select(state => state.Boundary).OrderBy(value => value).ToList();
                var previousBoundaries = states.Select(state => state.Boundary).OrderBy(value => value).ToList();
                terminalDiagnostic = $" stoppedAfterSection={section}; candidates={nextStates.Count}; boundaryRange={orderedBoundaries[0]}..{orderedBoundaries[^1]}; previousRange={previousBoundaries[0]}..{previousBoundaries[^1]}";
            }
            states = filteredStates;
            if (states.Count != 0)
                reachedSection = section;
        }

        var valid = states.Where(state => ValidateCandidate(transformed, state.Sections))
            .OrderBy(state => state.Score)
            .ToList();
        if (valid.Count == 0)
        {
            var best = states.OrderBy(state => state.Score).FirstOrDefault();
            var diagnostic = best == null ? string.Empty :
                $" Best unvalidated score={best.Score}, sections={string.Join(';', best.Sections.Select(section => $"{section.Offset}:{section.Size}"))}.";
            return HeaderSolveResult.Failure($"No structurally valid standard metadata header was reconstructed; search reached section {reachedSection + 1} of {RecordStrides.Length} with {states.Count} surviving layouts.{terminalDiagnostic}{diagnostic}");
        }
        var winner = valid[0];
        var competing = valid.Skip(1).Where(candidate => candidate.Score == winner.Score && !SameLayout(candidate, winner)).Take(3).ToList();
        if (competing.Count != 0)
            return HeaderSolveResult.Failure("Metadata header reconstruction was ambiguous and was rejected.");
        var output = (byte[])transformed.Clone();
        var header = new byte[304];
        BinaryPrimitives.WriteUInt32LittleEndian(header, Magic);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(4), metadataVersion);
        for (var index = 0; index < winner.Sections.Count; index++)
        {
            BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(8 + index * 8), winner.Sections[index].Offset);
            BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(12 + index * 8), winner.Sections[index].Size);
        }
        header.CopyTo(output, 0);
        return new HeaderSolveResult(true, output, winner.Score,
            winner.Sections.Select((section, index) => new SolvedMetadataSection(index, section.Offset, section.Size, RecordStrides[index])).ToList(), null);
    }

    private static IEnumerable<int> Adjustments(int stride)
    {
        yield return 0;
        if (stride <= 1)
            yield break;
        for (var delta = 4; delta <= stride; delta += 4)
        {
            yield return delta;
            yield return -delta;
        }
    }

    private static void AddState(List<SolveState> target, SolveState state, HeaderValue size, int actualSize, int boundary, int penalty,
                                 HeaderValue? boundarySource = null)
    {
        var used = new HashSet<int>(state.UsedFields);
        if (size.Field >= 0)
            used.Add(size.Field);
        if (boundarySource is { Field: >= 0 })
            used.Add(boundarySource.Field);
        var sections = new List<SectionPair>(state.Sections) { new(state.Boundary, actualSize) };
        target.Add(new SolveState(boundary, sections, used, state.Score + penalty));
    }

    private static bool ValidateCandidate(byte[] data, List<SectionPair> sections)
    {
        if (sections.Count != RecordStrides.Length)
            return false;
        var stringLiterals = sections[0];
        var literalData = sections[1];
        var stringHeap = sections[2];
        var sampleCount = Math.Min(256, stringLiterals.Size / 8);
        for (var index = 0; index < sampleCount; index++)
        {
            var position = stringLiterals.Offset + index * 8;
            var length = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(position, 4));
            var dataIndex = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(position + 4, 4));
            if (length > literalData.Size || dataIndex > literalData.Size - length)
                return false;
        }
        if (stringHeap.Size == 0)
            return false;
        var imageCount = sections[20].Size / 40;
        var assemblyCount = sections[21].Size / 64;
        return imageCount > 0 && imageCount == assemblyCount;
    }

    private static bool ValidatePartialCandidate(byte[] data, List<SectionPair> sections, int nextBoundary)
    {
        if (sections.Count == 0)
            return true;
        var latest = sections[^1];
        if (latest.Offset < 0 || latest.Size <= 0 || latest.Offset > data.Length - latest.Size)
            return false;
        if (sections.Count == 1)
        {
            if (latest.Size < 8_000 || latest.Size % 8 != 0)
                return false;
            var sampleCount = Math.Min(128, latest.Size / 8);
            for (var index = 0; index < sampleCount; index++)
            {
                var position = latest.Offset + index * 8;
                var length = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(position, 4));
                var dataIndex = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(position + 4, 4));
                if (length > 1_000_000 || dataIndex > data.Length)
                    return false;
            }
        }
        else if (sections.Count is 2 or 3 && latest.Size < 100_000)
        {
            return false;
        }
        else if (sections.Count == 3 && !LooksLikeTokenTable(data, latest.Offset + latest.Size, 24, 20, 0x14000000))
        {
            return false;
        }
        else if (sections.Count == 4)
        {
            var sampleCount = Math.Min(64, latest.Size / 24);
            if (sampleCount < 4)
                return false;
            var validTokens = 0;
            for (var index = 0; index < sampleCount; index++)
            {
                var token = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(latest.Offset + index * 24 + 20, 4));
                if ((token & 0xFF000000) == 0x14000000)
                    validTokens++;
            }
            if (validTokens * 10 < sampleCount * 9)
                return false;
            var followingTokenOffset = latest.Offset + latest.Size + 20;
            if (followingTokenOffset <= data.Length - 4)
            {
                var followingToken = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(followingTokenOffset, 4));
                if ((followingToken & 0xFF000000) == 0x14000000)
                    return false;
            }
        }
        else if (sections.Count == 5)
        {
            var sampleCount = Math.Min(64, latest.Size / 20);
            if (sampleCount < 4)
                return false;
            var validTokens = 0;
            for (var index = 0; index < sampleCount; index++)
            {
                var token = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(latest.Offset + index * 20 + 16, 4));
                if ((token & 0xFF000000) == 0x17000000)
                    validTokens++;
            }
            if (validTokens * 10 < sampleCount * 9)
                return false;
            var followingTokenOffset = latest.Offset + latest.Size + 16;
            if (followingTokenOffset <= data.Length - 4)
            {
                var followingToken = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(followingTokenOffset, 4));
                if ((followingToken & 0xFF000000) == 0x17000000)
                    return false;
            }
        }
        else if (sections.Count == 9 && latest.Size < 1_024)
        {
            return false;
        }
        else if (sections.Count == 11)
        {
            if (!LooksLikeParameterTable(data, latest.Offset) || !LooksLikeFieldTable(data, nextBoundary))
                return false;
        }
        else if (sections.Count == 19)
        {
            if (!LooksLikeTypeDefinitionTable(data, nextBoundary))
                return false;
        }
        else if (sections.Count == 20)
        {
            if (!LooksLikeImageTable(data, nextBoundary, 40 * 20))
                return false;
        }
        else if (sections.Count == 21)
        {
            var sampleCount = Math.Min(64, latest.Size / 40);
            if (sampleCount < 4)
                return false;
            var validRecords = 0;
            for (var index = 0; index < sampleCount; index++)
            {
                var position = latest.Offset + index * 40;
                var assemblyIndex = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(position + 4, 4));
                var typeStart = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(position + 8, 4));
                var typeCount = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(position + 12, 4));
                var token = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(position + 28, 4));
                if (assemblyIndex == index && typeStart >= 0 && typeCount >= 0 && token == 1)
                    validRecords++;
            }
            if (validRecords * 10 < sampleCount * 9)
                return false;
        }
        else if (sections.Count == 22 && !LooksLikeFieldRefs(data, nextBoundary))
        {
            return false;
        }
        else if (sections.Count == 23 && (!LooksLikeFieldRefs(data, latest.Offset) || LooksLikeFieldRefs(data, nextBoundary)))
        {
            return false;
        }
        else if (sections.Count == 25 && !LooksLikeAttributeDataRange(data, nextBoundary))
        {
            return false;
        }
        else
        {
            var index = sections.Count - 1;
            if (index is >= 12 and <= 18 && latest.Size < 100)
                return false;
            if (index == 19 && latest.Size < 1_000)
                return false;
            if (index is 20 or 21 && latest.Size < RecordStrides[index])
                return false;
            if (index is 22 or 23 or 25 or 26 or 27 && latest.Size < 100)
                return false;
            if (index == 24 && latest.Size < 1_000)
                return false;
        }
        return true;
    }

    private static bool LooksLikeImageTable(byte[] data, int offset, int bytesToCheck)
    {
        if (offset < 0 || bytesToCheck < 40 || offset > data.Length - bytesToCheck)
            return false;
        var count = bytesToCheck / 40;
        for (var index = 0; index < count; index++)
        {
            var position = offset + index * 40;
            var assemblyIndex = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(position + 4, 4));
            var typeStart = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(position + 8, 4));
            var typeCount = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(position + 12, 4));
            var token = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(position + 28, 4));
            if (assemblyIndex != index || typeStart < 0 || typeCount < 0 || token != 1)
                return false;
        }
        return true;
    }

    private static bool LooksLikeTypeDefinitionTable(byte[] data, int offset)
    {
        const int stride = 88;
        const int count = 20;
        if (offset < 0 || offset > data.Length - stride * count)
            return false;
        for (var index = 0; index < count; index++)
        {
            var position = offset + index * stride;
            var nameIndex = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(position, 4));
            var namespaceIndex = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(position + 4, 4));
            var token = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(position + 84, 4));
            if (nameIndex < 0 || namespaceIndex < 0 || (token & 0xFF000000) != 0x02000000)
                return false;
        }
        return true;
    }

    private static bool LooksLikeFieldTable(byte[] data, int offset)
    {
        const int stride = 12;
        const int count = 20;
        if (offset < 0 || offset > data.Length - stride * count)
            return false;
        for (var index = 0; index < count; index++)
        {
            var token = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset + index * stride + 8, 4));
            if ((token & 0xFF000000) != 0x04000000)
                return false;
        }
        return true;
    }

    private static bool LooksLikeParameterTable(byte[] data, int offset)
    {
        const int stride = 12;
        const int count = 32;
        if (offset < 0 || offset > data.Length - stride * count)
            return false;
        var firstNonZeroRid = -1;
        var previousRid = -1;
        for (var index = 0; index < count; index++)
        {
            var position = offset + index * stride;
            var nameIndex = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(position, 4));
            var token = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(position + 4, 4));
            var typeIndex = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(position + 8, 4));
            if (nameIndex < 0 || typeIndex < 0 || (token & 0xFF000000) != 0x08000000)
                return false;
            var rid = (int)(token & 0x00FFFFFF);
            if (index < 3 && rid != 0 || index == 3 && rid != 1)
                return false;
            if (rid == 0)
                continue;
            firstNonZeroRid = firstNonZeroRid < 0 ? rid : firstNonZeroRid;
            if (previousRid >= 0 && rid <= previousRid)
                return false;
            previousRid = rid;
        }
        return firstNonZeroRid is 1;
    }

    private static bool LooksLikeAttributeDataRange(byte[] data, int offset)
    {
        const int stride = 8;
        const int count = 32;
        if (offset < 0 || offset > data.Length - stride * count)
            return false;
        var previousStart = -1;
        for (var index = 0; index < count; index++)
        {
            var token = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset + index * stride, 4));
            var start = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset + index * stride + 4, 4));
            var tokenKind = token & 0xFF000000;
            if (index == 0 && (token != 0x02000002 || start != 0))
                return false;
            if (tokenKind is not (0x02000000 or 0x04000000 or 0x06000000 or 0x08000000 or 0x14000000 or 0x17000000) ||
                start < 0 || start < previousStart)
                return false;
            previousStart = start;
        }
        return true;
    }

    private static bool LooksLikeFieldRefs(byte[] data, int offset)
    {
        const int stride = 8;
        const int count = 32;
        if (offset < 0 || offset > data.Length - stride * count)
            return false;
        var previousType = -1;
        var previousField = -1;
        for (var index = 0; index < count; index++)
        {
            var type = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset + index * stride, 4));
            var field = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset + index * stride + 4, 4));
            if (type < 0 || field < 0 || type < previousType || type == previousType && field <= previousField)
                return false;
            previousType = type;
            previousField = field;
        }
        return true;
    }


    private static bool LooksLikeTokenTable(byte[] data, int offset, int stride, int tokenOffset, uint tokenKind)
    {
        const int count = 8;
        if (offset < 0 || offset > data.Length - stride * count)
            return false;
        for (var index = 0; index < count; index++)
        {
            var token = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset + index * stride + tokenOffset, 4));
            if ((token & 0xFF000000) != tokenKind)
                return false;
        }
        return true;
    }

    private static bool SameLayout(SolveState left, SolveState right) =>
        left.Sections.SequenceEqual(right.Sections);

    private static int ExportedTypeDefinitionPenalty(byte[] data, int offset, int size)
    {
        var count = Math.Min(64, size / 4);
        if (count < 8 || offset < 0 || offset > data.Length - count * 4)
            return 512;
        var penalty = 0;
        var previous = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset, 4));
        if (previous < 0)
            penalty += 64;
        for (var index = 1; index < count; index++)
        {
            var current = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset + index * 4, 4));
            if (current < 0 || Math.Abs((long)current - previous) > 64)
                penalty += 8;
            previous = current;
        }
        return penalty;
    }

    private sealed record HeaderValue(int Field, int Value);
    private sealed record SectionPair(int Offset, int Size);
    private sealed record SolveState(int Boundary, List<SectionPair> Sections, HashSet<int> UsedFields, int Score);
}

internal sealed record HeaderSolveResult(bool Success, byte[]? Data, int Score,
                                         List<SolvedMetadataSection> Sections, string? Error)
{
    public static HeaderSolveResult Failure(string error) => new(false, null, int.MaxValue, [], error);
}

internal sealed record SolvedMetadataSection(int Index, int Offset, int Size, int RecordStride);
