from find_sp2x_patches import find

if __name__ == "__main__":
    # DLL to search inside of
    dll_path = "./dlls/soundvoltex-1022.dll"
    # Signature to find all occurrences for
    signature = "E8 ?? ?? 2E 00 85 C0 0F 85 FA 00 00 00"
    # Offset to start searching at
    offset = 0

    print(dll_path)
    with open(dll_path, 'r+b') as dll:
        while True:
            offset = find(signature, dll, offset+1)
            if offset is None:
                break
            print(offset)