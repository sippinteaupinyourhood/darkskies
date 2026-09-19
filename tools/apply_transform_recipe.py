import argparse
import json
from pathlib import Path


def require_range(data, offset, size, label):
    if offset < 0 or size < 0 or offset > len(data) - size:
        raise ValueError(f"{label} is outside the metadata file: offset={offset}, size={size}")


def read_i32(data, offset):
    require_range(data, offset, 4, "header field")
    return int.from_bytes(data[offset:offset + 4], "little", signed=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("metadata")
    parser.add_argument("scan_report")
    parser.add_argument("--out", required=True)
    parser.add_argument("--report")
    args = parser.parse_args()

    metadata_path = Path(args.metadata).resolve()
    output_path = Path(args.out).resolve()
    if output_path == metadata_path or output_path.parent == metadata_path.parent:
        raise ValueError("Output must be outside the source metadata directory.")

    scan = json.loads(Path(args.scan_report).read_text(encoding="utf-8"))
    matches = [item for item in scan.get("candidates", []) if item.get("semanticMatch") == "metadata-section-transform"]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one metadata transform candidate, found {len(matches)}.")
    recipe = matches[0]
    header_recipe = recipe.get("headerTransform")
    if not header_recipe:
        raise ValueError("The scan report does not contain a recovered header transform.")

    source = bytearray(metadata_path.read_bytes())
    header_size = int(header_recipe["headerSize"])
    key_byte = int(header_recipe["keyByte"])
    require_range(source, 0, header_size, "protected header")
    for index in range(header_size):
        source[index] ^= (key_byte - index) & 0xFF
    header = bytes(source[:header_size])

    applied = []
    for descriptor in recipe["sectionPasses"]:
        source_offset = read_i32(header, int(descriptor["sourceOffsetField"])) + int(descriptor["sourceAdjustment"])
        length = read_i32(header, int(descriptor["lengthField"]))
        seed = header[int(descriptor["seedField"])]
        require_range(source, source_offset, length, "protected section")
        constant = int(descriptor["keyConstant"])
        subtract_seed = bool(descriptor["subtractSeed"])
        for index in range(length):
            key = index - seed + constant if subtract_seed else seed + index + constant
            source[source_offset + index] ^= key & 0xFF
        applied.append({"offset": source_offset, "size": length})

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(source)
    result = {
        "status": "transformed",
        "source": metadata_path.name,
        "output": output_path.name,
        "logicalTransformRva": recipe.get("logicalStartRva", recipe["rva"]),
        "headerTransform": header_recipe,
        "sectionPasses": applied,
        "observedHeaderPrefixAfterTransform": source[:8].hex().upper(),
    }
    report_path = Path(args.report).resolve() if args.report else output_path.with_suffix(output_path.suffix + ".json")
    report_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
