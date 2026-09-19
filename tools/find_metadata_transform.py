import argparse
import json
import struct
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP


def section_bytes(pe, image, name):
    section = next(section for section in pe.sections if section.Name.rstrip(b"\0").decode(errors="ignore") == name)
    start = section.PointerToRawData
    return section, memoryview(image)[start:start + section.SizeOfRawData]


def rva_to_offset(pe, rva):
    return pe.get_offset_from_rva(rva)


def runtime_functions(pe, image):
    section, data = section_bytes(pe, image, ".pdata")
    for offset in range(0, len(data) - 11, 12):
        begin, end, _ = struct.unpack_from("<III", data, offset)
        if begin and end > begin:
            yield begin, end


def analyze_function(md, code, va):
    byte_xors = 0
    indexed_memory = 0
    small_immediates = []
    backward_branches = 0
    header_displacements = []
    instruction_count = 0
    for instruction in md.disasm(code, va):
        instruction_count += 1
        operands = instruction.operands
        if instruction.mnemonic == "xor" and len(operands) == 2:
            left, right = operands
            if ((left.type == X86_OP_MEM and right.type == X86_OP_REG) or
                    (left.type == X86_OP_REG and right.type == X86_OP_MEM)) and min(left.size, right.size) == 1:
                byte_xors += 1
        for operand in operands:
            if operand.type != X86_OP_MEM:
                continue
            if operand.mem.index != 0:
                indexed_memory += 1
            displacement = operand.mem.disp
            if 0 <= displacement <= 0x200 and displacement % 4 == 0:
                header_displacements.append(displacement)
        if instruction.mnemonic in ("add", "sub") and len(operands) == 2 and operands[1].type == X86_OP_IMM:
            value = operands[1].imm
            if -256 <= value <= 256:
                small_immediates.append(value if instruction.mnemonic == "add" else -value)
        if instruction.mnemonic.startswith("j") and operands and operands[0].type == X86_OP_IMM and operands[0].imm < instruction.address:
            backward_branches += 1
    score = byte_xors * 20 + backward_branches * 5 + min(indexed_memory, 20) + min(len(set(header_displacements)), 20)
    return {
        "score": score,
        "byteXors": byte_xors,
        "backwardBranches": backward_branches,
        "indexedMemory": indexed_memory,
        "smallImmediates": sorted(set(small_immediates)),
        "headerDisplacements": sorted(set(header_displacements)),
        "instructionCount": instruction_count,
    }


def signed_immediate(instruction):
    if len(instruction.operands) != 2 or instruction.operands[1].type != X86_OP_IMM:
        return None
    value = instruction.operands[1].imm
    return value if instruction.mnemonic == "add" else -value


def memory_displacement(operand):
    return operand.mem.disp if operand.type == X86_OP_MEM else None


def extract_section_passes(instructions):
    passes = []
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic != "xor" or len(instruction.operands) != 2:
            continue
        destination, key = instruction.operands
        if destination.type != X86_OP_MEM or destination.size != 1 or key.type != X86_OP_REG or key.size != 1:
            continue
        window = instructions[max(0, index - 45):index]
        length_field = None
        seed_field = None
        source_field = None
        source_adjustment = 0
        key_constant = None
        subtract_seed = False
        for candidate in reversed(window):
            if length_field is None and candidate.mnemonic == "cmp" and candidate.operands:
                displacement = memory_displacement(candidate.operands[0])
                if displacement is not None and 0 <= displacement <= 0x400:
                    length_field = displacement
            if seed_field is None and candidate.mnemonic in ("add", "sub") and len(candidate.operands) == 2:
                displacement = memory_displacement(candidate.operands[1])
                if displacement is not None and candidate.operands[1].size == 1:
                    seed_field = displacement
                    subtract_seed = candidate.mnemonic == "sub"
            if key_constant is None and candidate.mnemonic in ("add", "sub", "lea"):
                if candidate.mnemonic in ("add", "sub"):
                    value = signed_immediate(candidate)
                    if value is not None and -255 <= value <= 255:
                        key_constant = value
                elif candidate.operands and candidate.operands[-1].type == X86_OP_MEM:
                    displacement = candidate.operands[-1].mem.disp
                    if -255 <= displacement <= 255:
                        key_constant = displacement
            if source_field is None and candidate.mnemonic == "mov" and len(candidate.operands) == 2:
                if candidate.operands[0].type == X86_OP_REG and candidate.reg_name(candidate.operands[0].reg) == "ecx":
                    displacement = memory_displacement(candidate.operands[1])
                    if displacement is not None and 0 <= displacement <= 0x400:
                        source_field = displacement
                        source_index = instructions.index(candidate)
                        for adjustment_instruction in instructions[source_index + 1:index]:
                            if adjustment_instruction.mnemonic in ("add", "sub") and len(adjustment_instruction.operands) == 2:
                                if adjustment_instruction.operands[0].type == X86_OP_REG and adjustment_instruction.reg_name(adjustment_instruction.operands[0].reg) == "ecx":
                                    value = signed_immediate(adjustment_instruction)
                                    if value is not None:
                                        source_adjustment = value
                                        break
            if all(value is not None for value in (length_field, seed_field, source_field, key_constant)):
                break
        if all(value is not None for value in (length_field, seed_field, source_field, key_constant)):
            descriptor = {
                "sourceOffsetField": source_field,
                "sourceAdjustment": source_adjustment,
                "lengthField": length_field,
                "seedField": seed_field,
                "subtractSeed": subtract_seed,
                "keyConstant": key_constant,
                "loopAddress": f"0x{instruction.address:X}",
            }
            if not passes or descriptor["loopAddress"] != passes[-1]["loopAddress"]:
                passes.append(descriptor)
    return passes


def masked_signature(instructions, center_address, radius=48):
    selected = [item for item in instructions if center_address - radius <= item.address < center_address + radius]
    if not selected:
        return None
    data = bytearray()
    mask = bytearray()
    for instruction in selected:
        encoded = bytearray(instruction.bytes)
        encoded_mask = bytearray(b"\xFF" * len(encoded))
        if instruction.disp_size:
            encoded_mask[instruction.disp_offset:instruction.disp_offset + instruction.disp_size] = b"\0" * instruction.disp_size
        if instruction.imm_size:
            encoded_mask[instruction.imm_offset:instruction.imm_offset + instruction.imm_size] = b"\0" * instruction.imm_size
        data.extend(encoded)
        mask.extend(encoded_mask)
    tokens = [f"{byte:02X}" if keep else "??" for byte, keep in zip(data, mask)]
    return " ".join(tokens)


def read_virtual(pe, image, address, size):
    rva = address - pe.OPTIONAL_HEADER.ImageBase
    try:
        offset = pe.get_offset_from_rva(rva)
    except Exception:
        return None
    if offset < 0 or offset > len(image) - size:
        return None
    return image[offset:offset + size]


def extract_header_transform(pe, image, instructions):
    allocation_sizes = []
    header_sizes = []
    uniform_references = []
    for instruction in instructions:
        if instruction.mnemonic in ("mov", "cmp"):
            for operand in instruction.operands:
                if operand.type == X86_OP_IMM and 0x100 <= operand.imm <= 0x800 and operand.imm % 4 == 0:
                    header_sizes.append((instruction.address, operand.imm))
        if instruction.mnemonic == "mov" and len(instruction.operands) == 2:
            if (instruction.operands[0].type == X86_OP_REG and instruction.reg_name(instruction.operands[0].reg) == "ecx" and
                    instruction.operands[1].type == X86_OP_IMM and 0x100 <= instruction.operands[1].imm <= 0x800):
                position = instructions.index(instruction)
                if any(item.mnemonic == "call" for item in instructions[position + 1:position + 4]):
                    allocation_sizes.append((instruction.address, instruction.operands[1].imm))
        for operand in instruction.operands:
            if operand.type != X86_OP_MEM or operand.mem.base != X86_REG_RIP:
                continue
            target = instruction.address + instruction.size + operand.mem.disp
            value = read_virtual(pe, image, target, 16)
            if value and value[0] and len(set(value)) == 1:
                uniform_references.append((instruction.address, value[0]))
    if not header_sizes or not uniform_references:
        return None
    from collections import Counter
    size_source = allocation_sizes or header_sizes
    header_size = Counter(value for _, value in size_source).most_common(1)[0][0]
    allocation_address = min(address for address, value in size_source if value == header_size)
    key_candidates = [value for address, value in uniform_references if address > allocation_address]
    if not key_candidates:
        return None
    return {
        "headerSize": header_size,
        "keyByte": Counter(key_candidates).most_common(1)[0][0],
        "operation": "byte ^= (keyByte - index) & 0xFF",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("game_assembly")
    parser.add_argument("--out", required=True)
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()

    path = Path(args.game_assembly)
    image = path.read_bytes()
    pe = pefile.PE(data=image, fast_load=True)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    candidates = []
    functions = list(runtime_functions(pe, image))
    previous_by_end = {end: begin for begin, end in functions}
    for begin, end in functions:
        size = end - begin
        if size < 24 or size > 0x5000:
            continue
        try:
            offset = rva_to_offset(pe, begin)
        except Exception:
            continue
        code = image[offset:offset + size]
        memory_xor_opcodes = sum(1 for index in range(len(code) - 1)
                                 if code[index] in (0x30, 0x32) and (code[index + 1] & 0xC0) != 0xC0)
        if memory_xor_opcodes < 5:
            continue
        function_va = pe.OPTIONAL_HEADER.ImageBase + begin
        result = analyze_function(md, code, function_va)
        if result["byteXors"] < 2:
            continue
        instructions = list(md.disasm(code, function_va))
        passes = extract_section_passes(instructions)
        result.update({"rva": f"0x{begin:X}", "va": f"0x{function_va:X}", "size": size})
        if len(passes) >= 5:
            result["semanticMatch"] = "metadata-section-transform"
            result["sectionPasses"] = passes
            result["maskedSignature"] = masked_signature(instructions, int(passes[0]["loopAddress"], 16))
            header_transform = extract_header_transform(pe, image, instructions)
            if header_transform:
                result["headerTransform"] = header_transform
                result["logicalStartRva"] = f"0x{begin:X}"
            predecessor = previous_by_end.get(begin)
            if "headerTransform" not in result and predecessor is not None and begin - predecessor <= 0x800:
                predecessor_offset = rva_to_offset(pe, predecessor)
                predecessor_code = image[predecessor_offset:predecessor_offset + begin - predecessor]
                predecessor_instructions = list(md.disasm(predecessor_code, pe.OPTIONAL_HEADER.ImageBase + predecessor))
                header_transform = extract_header_transform(pe, image, predecessor_instructions + instructions)
                if header_transform:
                    result["headerTransform"] = header_transform
                    result["logicalStartRva"] = f"0x{predecessor:X}"
            result["score"] += 500 + len(passes) * 50
        candidates.append(result)
    candidates.sort(key=lambda item: (item["score"], item["byteXors"], item["backwardBranches"]), reverse=True)
    output = {"gameAssembly": str(path.name), "candidateCount": len(candidates), "candidates": candidates[:args.limit]}
    Path(args.out).write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
