from find_sp2x_patches import find
from pathlib import Path

if __name__ == "__main__":
    # Path to recursively find dll files under
    dll_path = "./dlls/"
    # Signature to find all occurrences for
    signature = ""
    # Offset to start searching at
    start_offset = 0
    # Adjustement to add to the output offset
    adjust = 0

    for dll_path in Path(dll_path).rglob("*.dll"):
        offset = start_offset
        print(dll_path)
        with open(dll_path, 'r+b') as dll:
            while True:
                offset = find(signature, dll, offset+1, adjust)
                if offset is None:
                    break
                print(offset, signature.replace(" ", "")[adjust*2:])