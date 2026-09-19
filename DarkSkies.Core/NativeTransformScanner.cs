using System.Buffers.Binary;
using Iced.Intel;

internal static class NativeTransformScanner
{
    public static IEnumerable<string> Disassemble(PortableExecutable image, uint rva, uint size) =>
        Decode(image, rva, size).Select(instruction => $"{instruction.IP:X16} {instruction}");

    public static NativeTransformApplication Apply(byte[] source, NativeTransformReport recipe)
    {
        var candidates = new List<NativeTransformApplication>();
        foreach (var subtractIndex in new[] { true, false })
        {
            try { candidates.Add(Apply(source, recipe, subtractIndex)); }
            catch (Exception exception) when (exception is InvalidDataException or OverflowException or ArgumentException) { }
        }
        return candidates.Count switch
        {
            1 => candidates[0],
            0 => throw new InvalidDataException("Neither native header-key direction produced valid metadata section ranges."),
            _ => throw new InvalidDataException("Both native header-key directions produced plausible ranges; the transform is ambiguous.")
        };
    }

    private static NativeTransformApplication Apply(byte[] source, NativeTransformReport recipe, bool subtractIndex)
    {
        var output = (byte[])source.Clone();
        var headerSize = recipe.HeaderTransform.HeaderSize;
        EnsureRange(output, 0, headerSize, "protected header");
        for (var index = 0; index < headerSize; index++)
            output[index] ^= (byte)(subtractIndex
                ? recipe.HeaderTransform.KeyByte - index
                : recipe.HeaderTransform.KeyByte + index);
        var header = output.AsSpan(0, headerSize).ToArray();
        var ranges = new List<NativeTransformRange>();
        foreach (var pass in recipe.SectionPasses)
        {
            var offset = checked(ReadInt32(header, pass.SourceOffsetField) + pass.SourceAdjustment);
            var size = ReadInt32(header, pass.LengthField);
            EnsureRange(output, offset, size, "protected section");
            var seed = header[pass.SeedField];
            for (var index = 0; index < size; index++)
            {
                var key = pass.SubtractSeed
                    ? index - seed + pass.KeyConstant
                    : seed + index + pass.KeyConstant;
                output[offset + index] ^= (byte)key;
            }
            ranges.Add(new NativeTransformRange(offset, size));
        }
        return new NativeTransformApplication(output, ranges,
            subtractIndex ? "byte ^= (keyByte - index) & 0xFF" : "byte ^= (keyByte + index) & 0xFF");
    }

    public static NativeTransformReport? Scan(PortableExecutable image)
    {
        var pdata = image.Sections.SingleOrDefault(section => section.Name == ".pdata");
        if (pdata == null)
            return null;
        var functions = ReadRuntimeFunctions(pdata).ToList();
        var predecessors = functions.ToDictionary(item => item.End, item => item.Begin);
        var matches = new List<NativeTransformReport>();
        foreach (var function in functions)
        {
            var size = function.End - function.Begin;
            if (size is < 24 or > 0x5000)
                continue;
            List<Instruction> instructions;
            try
            {
                instructions = Decode(image, function.Begin, size);
            }
            catch (BadImageFormatException)
            {
                continue;
            }
            var passes = ExtractPasses(instructions);
            if (passes.Count < 5)
                continue;
            var logicalStart = function.Begin;
            var headerInstructions = instructions;
            var header = ExtractHeader(image, headerInstructions);
            if (header == null && predecessors.TryGetValue(function.Begin, out var predecessor) && function.Begin - predecessor <= 0x800)
            {
                var previous = functions.First(item => item.Begin == predecessor);
                headerInstructions = Decode(image, previous.Begin, previous.End - previous.Begin).Concat(instructions).ToList();
                header = ExtractHeader(image, headerInstructions);
                if (header != null)
                    logicalStart = predecessor;
            }
            if (header == null)
                continue;
            matches.Add(new NativeTransformReport(
                "metadata-section-transform",
                $"0x{logicalStart:X}",
                $"0x{function.Begin:X}",
                header,
                passes,
                BuildSemanticFingerprint(passes),
                passes.Count == 7 ? "high" : "candidate"));
        }
        return matches.Count == 1 ? matches[0] : null;
    }

    private static IEnumerable<(uint Begin, uint End)> ReadRuntimeFunctions(PeSection pdata)
    {
        for (var offset = 0; offset <= pdata.Data.Length - 12; offset += 12)
        {
            var begin = BinaryPrimitives.ReadUInt32LittleEndian(pdata.Data.AsSpan(offset, 4));
            var end = BinaryPrimitives.ReadUInt32LittleEndian(pdata.Data.AsSpan(offset + 4, 4));
            if (begin != 0 && end > begin)
                yield return (begin, end);
        }
    }

    private static List<Instruction> Decode(PortableExecutable image, uint rva, uint size)
    {
        var bytes = image.ReadVirtual(image.ImageBase + rva, checked((int)size));
        var decoder = Decoder.Create(64, new ByteArrayCodeReader(bytes));
        decoder.IP = image.ImageBase + rva;
        var endAddress = decoder.IP + size;
        var result = new List<Instruction>();
        while (decoder.IP < endAddress)
        {
            decoder.Decode(out var instruction);
            if (instruction.IsInvalid)
                break;
            result.Add(instruction);
        }
        return result;
    }

    private static List<NativeSectionPass> ExtractPasses(List<Instruction> instructions)
    {
        var result = new List<NativeSectionPass>();
        for (var index = 0; index < instructions.Count; index++)
        {
            var instruction = instructions[index];
            if (instruction.Mnemonic != Mnemonic.Xor || instruction.Op0Kind != OpKind.Memory ||
                instruction.Op1Kind != OpKind.Register || instruction.Op1Register != Register.AL)
                continue;
            int? lengthField = null;
            int? seedField = null;
            int? sourceField = null;
            var sourceAdjustment = 0;
            int? keyConstant = null;
            var subtractSeed = false;
            var start = Math.Max(0, index - 45);
            for (var cursor = index - 1; cursor >= start; cursor--)
            {
                var candidate = instructions[cursor];
                if (lengthField == null && candidate.Mnemonic == Mnemonic.Cmp && candidate.Op0Kind == OpKind.Memory)
                    lengthField = HeaderDisplacement(candidate);
                if (seedField == null && candidate.Mnemonic is Mnemonic.Add or Mnemonic.Sub && candidate.Op1Kind == OpKind.Memory)
                {
                    seedField = HeaderDisplacement(candidate);
                    subtractSeed = candidate.Mnemonic == Mnemonic.Sub;
                }
                if (keyConstant == null)
                {
                    if (candidate.Mnemonic is Mnemonic.Add or Mnemonic.Sub && candidate.Op0Kind == OpKind.Register && candidate.Op0Register == Register.AL)
                    {
                        var immediate = SignedImmediate(candidate);
                        if (immediate is >= -255 and <= 255)
                            keyConstant = immediate;
                    }
                    else if (candidate.Mnemonic == Mnemonic.Lea && candidate.Op0Kind == OpKind.Register && candidate.Op0Register == Register.EAX && candidate.MemoryBase == Register.RCX)
                    {
                        var displacement = unchecked((int)candidate.MemoryDisplacement64);
                        if (displacement is >= -255 and <= 255)
                            keyConstant = displacement;
                    }
                }
                if (sourceField == null && candidate.Mnemonic == Mnemonic.Mov && candidate.Op0Kind == OpKind.Register &&
                    candidate.Op0Register == Register.ECX && candidate.Op1Kind == OpKind.Memory)
                {
                    sourceField = HeaderDisplacement(candidate);
                    for (var adjustmentIndex = cursor + 1; adjustmentIndex < index; adjustmentIndex++)
                    {
                        var adjustment = instructions[adjustmentIndex];
                        if (adjustment.Mnemonic is not (Mnemonic.Add or Mnemonic.Sub) || adjustment.Op0Kind != OpKind.Register || adjustment.Op0Register != Register.ECX)
                            continue;
                        sourceAdjustment = SignedImmediate(adjustment) ?? 0;
                        break;
                    }
                }
                if (lengthField != null && seedField != null && sourceField != null && keyConstant != null)
                    break;
            }
            if (lengthField is not >= 0 || seedField is not >= 0 || sourceField is not >= 0 || keyConstant == null)
                continue;
            result.Add(new NativeSectionPass(sourceField.Value, sourceAdjustment, lengthField.Value, seedField.Value,
                                             subtractSeed, keyConstant.Value, $"0x{instruction.IP:X}"));
        }
        return result;
    }

    private static NativeHeaderTransform? ExtractHeader(PortableExecutable image, List<Instruction> instructions)
    {
        var allocations = new List<(ulong Address, int Size)>();
        var uniformConstants = new List<(ulong Address, byte Value)>();
        for (var index = 0; index < instructions.Count; index++)
        {
            var instruction = instructions[index];
            if (instruction.Mnemonic == Mnemonic.Mov && instruction.Op0Kind == OpKind.Register && instruction.Op0Register == Register.ECX)
            {
                var value = Immediate(instruction);
                if (value is >= 0x100 and <= 0x800 && instructions.Skip(index + 1).Take(3).Any(item => item.Mnemonic == Mnemonic.Call))
                    allocations.Add((instruction.IP, value.Value));
            }
            if (!instruction.IsIPRelativeMemoryOperand)
                continue;
            try
            {
                var bytes = image.ReadVirtual(instruction.IPRelativeMemoryAddress, 16);
                if (bytes[0] != 0 && bytes.All(value => value == bytes[0]))
                    uniformConstants.Add((instruction.IP, bytes[0]));
            }
            catch (BadImageFormatException)
            {
            }
        }
        if (allocations.Count == 0)
            return null;
        var allocation = allocations.GroupBy(item => item.Size).OrderByDescending(group => group.Count()).First().First();
        var keys = uniformConstants.Where(item => item.Address > allocation.Address).ToList();
        if (keys.Count == 0)
            return null;
        var key = keys.GroupBy(item => item.Value).OrderByDescending(group => group.Count()).First().Key;
        return new NativeHeaderTransform(allocation.Size, key, "byte ^= (keyByte - index) & 0xFF");
    }

    private static int? HeaderDisplacement(Instruction instruction)
    {
        if (instruction.MemoryBase == Register.None || instruction.MemoryIndex != Register.None)
            return null;
        var displacement = unchecked((int)instruction.MemoryDisplacement64);
        return displacement is >= 0 and <= 0x400 ? displacement : null;
    }

    private static int? SignedImmediate(Instruction instruction)
    {
        var value = Immediate(instruction);
        if (value == null)
            return null;
        return instruction.Mnemonic == Mnemonic.Sub ? -value : value;
    }

    private static int? Immediate(Instruction instruction)
    {
        var kind = instruction.OpCount > 1 ? instruction.Op1Kind : instruction.Op0Kind;
        return kind switch
        {
            OpKind.Immediate8 => instruction.Immediate8,
            OpKind.Immediate8to32 => instruction.Immediate8to32,
            OpKind.Immediate8to64 => checked((int)instruction.Immediate8to64),
            OpKind.Immediate32 => unchecked((int)instruction.Immediate32),
            OpKind.Immediate32to64 => checked((int)instruction.Immediate32to64),
            _ => null
        };
    }

    private static string BuildSemanticFingerprint(List<NativeSectionPass> passes) =>
        string.Join(";", passes.Select(item => $"{item.SourceOffsetField}:{item.SourceAdjustment}:{item.LengthField}:{item.SeedField}:{(item.SubtractSeed ? 'S' : 'A')}:{item.KeyConstant}"));

    private static int ReadInt32(byte[] data, int offset)
    {
        EnsureRange(data, offset, 4, "header field");
        return BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset, 4));
    }

    private static void EnsureRange(byte[] data, int offset, int size, string label)
    {
        if (offset < 0 || size < 0 || offset > data.Length - size)
            throw new InvalidDataException($"The {label} is outside the metadata file.");
    }
}

internal sealed record NativeTransformReport(string Kind,
                                             string LogicalStartRva,
                                             string RuntimeFunctionRva,
                                             NativeHeaderTransform HeaderTransform,
                                             List<NativeSectionPass> SectionPasses,
                                             string SemanticFingerprint,
                                             string Confidence);
internal sealed record NativeHeaderTransform(int HeaderSize, byte KeyByte, string Operation);
internal sealed record NativeSectionPass(int SourceOffsetField,
                                         int SourceAdjustment,
                                         int LengthField,
                                         int SeedField,
                                         bool SubtractSeed,
                                         int KeyConstant,
                                         string LoopAddress);
internal sealed record NativeTransformApplication(byte[] Data, List<NativeTransformRange> Ranges, string HeaderOperation);
internal sealed record NativeTransformRange(int Offset, int Size);
