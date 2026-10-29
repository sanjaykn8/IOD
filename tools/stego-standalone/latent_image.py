"""Deterministic procedural latent images with lossless UTF-8 steganography.

Thin compatibility wrapper: the generator and the legacy embed/extract now live
in ``stego.procedural`` (python-service/src) so the service and this tool share
one implementation. The CLI (generate / extract) is unchanged.
"""
import argparse
import sys
from pathlib import Path

_SERVICE_SRC = str(Path(__file__).resolve().parent / ".." / ".." / "python-service" / "src")
if _SERVICE_SRC not in sys.path:
    sys.path.insert(0, _SERVICE_SRC)

import numpy as np  # noqa: E402

from stego.procedural import (  # noqa: E402,F401
    BW_MAGIC,
    HEADER,
    MAGIC,
    decode_latent,
    embed,
    embed_bytes,
    encode_text,
    extract,
    extract_bytes,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("generate")
    inputs = generate.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--text", help="Text or hash, preserved exactly")
    inputs.add_argument("--input-file", type=Path, help="UTF-8 text file")
    generate.add_argument("--output", type=Path, default=Path("output.png"))
    generate.add_argument("--size", type=int, default=512)
    generate.add_argument("--latent-output", type=Path, help="Optionally save the vector as .npy")
    recover = commands.add_parser("extract")
    recover.add_argument("image", type=Path)
    recover.add_argument("--output", type=Path, help="Save recovered UTF-8 text")
    args = parser.parse_args()
    try:
        if args.command == "generate":
            if not 32 <= args.size <= 2048:
                raise ValueError("Size must be between 32 and 2048.")
            if args.output.suffix.lower() != ".png":
                raise ValueError("Use a .png output to preserve hidden data.")
            text = args.text if args.text is not None else args.input_file.read_bytes().decode("utf-8")
            capacity = args.size * args.size // 16 - HEADER.size
            if len(text.encode("utf-8")) > capacity:
                raise ValueError(f"Input exceeds capacity of {capacity} UTF-8 bytes.")
            latent = encode_text(text)
            embed(decode_latent(latent, args.size), text).save(args.output, format="PNG")
            if args.latent_output:
                np.save(args.latent_output, latent, allow_pickle=False)
            print(f"Saved {args.output}; hidden payload verified: {extract(args.output) == text}")
        else:
            text = extract(args.image)
            if args.output:
                args.output.write_bytes(text.encode("utf-8"))
                print(f"Saved recovered text to {args.output}")
            else:
                print(text)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
