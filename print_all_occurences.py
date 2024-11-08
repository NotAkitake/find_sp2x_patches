from find_sp2x_patches import find

if __name__ == "__main__":
    # DLL to search inside of
    dll_path = "./dlls/file.dll"
    # Signature to find all occurrences for
    signature = ""
    # Offset to start searching at
    offset = 0

    print(dll_path)
    with open(dll_path, 'r+b') as dll:
        while True:
            offset = find(signature, dll, offset+1)
            if offset is None:
                break
            print(offset)