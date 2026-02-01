#!/usr/bin/env python3
"""
Batch extract PBKDF2 iteration count from multiple Bitcoin Core wallet.dat files
Outputs JSON array with one object per file.

Usage examples:
  # Single file
  python3 extract_iterations_batch.py wallet.dat

  # Multiple files
  python3 extract_iterations_batch.py wallet1.dat wallet2.dat backup/*.dat

  # All .dat files in current directory
  python3 extract_iterations_batch.py *.dat

  # All .dat files in a folder
  python3 extract_iterations_batch.py /path/to/wallets/*.dat

Output is always valid JSON — even if some files fail.
"""

import sys
import json
import struct
from pathlib import Path

def extract_iterations(file_path: str) -> dict:
    path = Path(file_path)
    result = {"file": str(path.absolute()), "status": "error"}

    try:
        with open(path, "rb") as f:
            data = f.read()

        mkey_offset = data.find(b'\x04mkey\x01\x00\x00\x00')
        if mkey_offset == -1:
            result["error"] = "mkey record not found (not encrypted or not Bitcoin Core wallet?)"
            return result

        start = mkey_offset + 8
        iter_bytes = data[start + 48 + 8 + 4 : start + 48 + 8 + 4 + 4]

        if len(iter_bytes) < 4:
            result["error"] = "iteration count field too short / corrupted"
            return result

        iterations = struct.unpack("<I", iter_bytes)[0]

        result.update({
            "status": "ok",
            "iterations": {
                "decimal": iterations,
                "hex": f"0x{iterations:x}"
            }
        })

    except FileNotFoundError:
        result["error"] = "file not found"
    except PermissionError:
        result["error"] = "permission denied"
    except Exception as e:
        result["error"] = f"unexpected error: {str(e)}"

    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({
            "error": "No files specified",
            "usage": "python3 extract_iterations_batch.py <wallet1.dat> [wallet2.dat ...]"
        }, indent=2))
        sys.exit(1)

    results = []

    # Process every argument after the script name
    for arg in sys.argv[1:]:
        path = Path(arg)
        if path.is_dir():
            # If it's a directory → find all .dat files inside
            for dat_file in path.glob("*.dat"):
                results.append(extract_iterations(dat_file))
        elif path.is_file() and path.suffix.lower() == ".dat":
            results.append(extract_iterations(path))
        else:
            results.append({
                "file": arg,
                "status": "skipped",
                "reason": "not a .dat file or not found"
            })

    # Output clean JSON array
    print(json.dumps(results, indent=2))

    # Exit code: 0 if all succeeded, 1 if any had error
    all_ok = all(r.get("status") == "ok" for r in results if r.get("status") != "skipped")
    sys.exit(0 if all_ok else 1)
