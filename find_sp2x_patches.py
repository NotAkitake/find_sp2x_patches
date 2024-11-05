import argparse
import datetime
import json
import logging
import io
from typing import BinaryIO
from venv import logger
import pefile
import re
import struct
from datetime import timezone
from pathlib import Path


class MemorySubPatch:
    def __init__(self, offset: int, dll_name: str, data_disabled: str, data_enabled: str):
        self.offset = offset
        self.dll_name = dll_name
        self.data_disabled = data_disabled.replace(" ", "")
        self.data_enabled = data_enabled.replace(" ", "").replace("NUL", "0" * len(data_disabled))

    def to_dict(self):
        return {
            "offset": self.offset,
            "dllName": self.dll_name,
            "dataDisabled": self.data_disabled,
            "dataEnabled": self.data_enabled,
        }

    def __str__(self):
        return json.dumps(self.to_dict(), indent = 4)


class MemoryPatch:
    def __init__(self, name: str, description: str, game_code: str, patches: list[MemorySubPatch], caution: str = None):
        self.name = name
        self.description = description
        self.caution = caution
        self.game_code = game_code
        self.patches = patches


    def to_dict(self):
        memdict = {
            "type": "memory",
            "name": self.name,
            "description": self.description,
            "caution": self.caution,
            "gameCode": self.game_code,
            "patches": [subpatch.to_dict() for subpatch in self.patches]
        }
        memdict = {k: v for k, v in memdict.items() if v is not None}
        return memdict


    def __str__(self):
        return json.dumps(self.to_dict(), indent = 4)


class UnionSubPatch:
    def __init__(self, name: str,  offset: int, dll_name: str, data: str):
        self.name = name
        self.offset = offset
        self.dll_name = dll_name
        self.data = data.replace(" ", "")

    def to_dict(self):
        return {
            "name": self.name,
            "patch": {
                "offset": self.offset,
                "dllName": self.dll_name,
                "data": self.data
            }
        }

    def __str__(self):
        return json.dumps(self.to_dict(), indent=4)


class UnionPatch:
    def __init__(self, name: str, description: str, game_code: str, patches: list[UnionSubPatch], caution: str = None):
        self.name = name
        self.description = description
        self.caution = caution
        self.game_code = game_code
        self.patches = patches


    def to_dict(self):
        uniondict = {
            "type": "union",
            "name": self.name,
            "description": self.description,
            "caution": self.caution,
            "gameCode": self.game_code,
            "patches": [subpatch.to_dict() for subpatch in self.patches]
        }
        uniondict = {k: v for k, v in uniondict.items() if v is not None}
        return uniondict


    def __str__(self):
        return json.dumps(self.to_dict(), indent=4)


class NumberPatch:
    def __init__(self, name: str, description: str, game_code: str, dll_name: str, offset: int, size: int, i_min: int, i_max: int, caution: str = None):
        self.name = name
        self.description = description
        self.caution = caution
        self.game_code = game_code
        self.dll_name = dll_name
        self.offset = offset
        self.size = size
        self.i_min = i_min
        self.i_max = i_max


    def to_dict(self) -> dict:
        numdict = {
            "type": "number",
            "name": self.name,
            "description": self.description,
            "caution": self.caution,
            "gameCode": self.game_code,
            "patch": {
                "dllName": self.dll_name,
                "offset": self.offset,
                "size": self.size,
                "min": self.i_min,
                "max":self.i_max
            }
        }
        numdict = {k: v for k, v in numdict.items() if v is not None}
        return numdict


    def __str__(self):
        return json.dumps(self.to_dict(), indent = 4)


def signature_to_regex(signature: str) -> str:
    """
    Converts a wildcarded signature into a regex pattern.
    :param signature: Allows '??' for wildcard bytes, for example: 'E8 45 15 ?? 00 00'
    :return: regex pattern
    """
    pattern: list[str] = []
    for byte in signature.split():
        if byte == '??':
            pattern.append('.{2}')
        else:
            pattern.append(re.escape(byte))

    return ''.join(pattern)


def find(signature: str, dll: BinaryIO, start_offset: int = 0, adjust: int = 0) -> int or None:
    """
    Finds a wildcarded bytes signature inside a dll's hex data.
    :param signature: Allows '??' for wildcard bytes, for example: 'E8 45 15 ?? 00 00'.
    :param dll: Dll file opened in binary mode.
    :param start_offset: (optional) decimal offset to start the search at, default: 0.
    :param adjust: (optional) Value added to the returned decimal offset, default: 0.
    :return: decimal offset if a match is found, otherwise None.
    """
    signature_regex = signature_to_regex(signature)

    # Place cursor at start_offset
    dll.seek(start_offset)
    # Read all hex data from cursor to EOF
    data = dll.read()
    hex_data = data.hex().upper()

    # Search for the regex signature
    match = re.search(signature_regex, hex_data)
    if match:
        # If a match is found, calculate the final offset and return it
        offset = int(match.start() / 2) + start_offset + adjust
        return offset
    return None


def read_dword(dll: BinaryIO, offset: int) -> int:
    """
    Reads and returns dword in file (open as r+b) at offset.
    :param dll: Dll file opened in binary mode.
    :param offset: Offset to read the dword from.
    :return: struct: Unpacked dword.
    """
    dll.seek(offset)
    return struct.unpack('<I', dll.read(4))[0]


def get_identifier(game_code: str, dll: BinaryIO) -> str:
    """
    Concatenates 'game_code' with the PE identifier for 'dll'.
    :param game_code: Game code for the dll (KFC, LDJ, M39, ...).
    :param dll: Dll file opened in binary mode.
    :return: Identifier for the dll.
    """
    try:
        # Read DOS header to get PE header offset
        pe_header_offset = read_dword(dll, 0x3c)

        # Check for "PE\0\0" signature
        dll.seek(pe_header_offset)
        if dll.read(4) != b'PE\0\0':
            raise ValueError(f"File '{dll}' is not a valid PE file.")

        # Read TimeDateStamp
        timestamp = read_dword(dll, pe_header_offset + 8)

        # Read AddressOfEntryPoint
        optional_header_offset = pe_header_offset + 24
        entry_point = read_dword(dll, optional_header_offset + 16)

        # Concatenate GameCode, TimeDateStamp, and AddressOfEntryPoint    
        identifier = f"{game_code.upper()}-{timestamp:x}_{entry_point:x}"
        return identifier
    except Exception as e:
        print(f"Error getting identifier from file: {e}")
        raise


def parse_args() -> argparse.Namespace:
    """
    Parses script arguments.
    :return: Parsed arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--game',
        default='ALL',
        help='(optional) Set a specific game to run the script for (example: KFC, default: ALL)'
    )
    parser.add_argument(
        '--loglevel',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='(optional) Set the console logging level (default: INFO)'
    )
    return parser.parse_args()


def set_logger(loglevel: str) -> None:
    """
    Sets logger custom formatting and loglevel.
    :param loglevel: Loglevel applied to the console only (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    :return: None
    """
    # Create a custom logger
    logger.setLevel(logging.DEBUG)

    # Create a file handler with UTF-8 encoding
    file_handler: logging.FileHandler = logging.FileHandler("logs.txt", mode="w", encoding="utf-8")
    console_handler: logging.StreamHandler = logging.StreamHandler()

    # Set the logging level for handlers
    file_handler.setLevel(logging.DEBUG)
    console_handler.setLevel(loglevel)

    # Create a custom formatter for the console with colors based on log levels
    class CustomFormatter(logging.Formatter):
        # Define color mappings for different log levels
        FORMATS = {
            logging.DEBUG: "\033[36m%(asctime)s - %(levelname)s: %(message)s",
            logging.INFO: "\033[32m%(asctime)s - %(levelname)s: %(message)s",
            logging.WARNING: "\033[33m%(asctime)s - %(levelname)s: %(message)s",
            logging.ERROR: "\033[31m%(asctime)s - %(levelname)s: %(message)s",
            logging.CRITICAL: "\033[35m%(asctime)s - %(levelname)s: %(message)s",
        }

        def format(self, record):
            log_fmt = self.FORMATS.get(record.levelno, "%(asctime)s - %(levelname)s: %(message)s")
            formatter = logging.Formatter(log_fmt)
            return formatter.format(record)

    # Apply different formatters to the file and console handlers
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
    file_handler.setFormatter(file_formatter)
    console_handler.setFormatter(CustomFormatter())

    # Add handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

# HIDE PREMIUM GUIDE BANNER
def kfc_001(dll: BinaryIO, dll_path: str, dll_name: str, game_code: str, name: str, description: str, caution: str = None) -> MemoryPatch | None:
    pe = pefile.PE(dll_path, fast_load=True)

    # Signature is 'pt_sousa_usr'
    offset = find("70 74 5F 73 6F 75 73 61 5F 75 73 72", dll)
    if offset is None: return None
    pt = pe.get_rva_from_offset(offset)
    offset = find("00 44 89 44 24 28 48 8D 45", dll, 2090000)
    if offset is None: return None
    for _ in range(4):
        offset = find("45 33 C0", dll, offset, 6)
        if offset is None: return None

    data_enabled = struct.pack("<i", pt - pe.get_rva_from_offset(offset) - 4).hex().upper()
    dll.seek(offset)
    data_disabled = dll.read(round(len(data_enabled) / 2)).hex().upper()

    subpatch = MemorySubPatch(offset, dll_name, data_disabled, data_enabled)
    return MemoryPatch(name, description, game_code, [ subpatch ], caution)

# FAKE REGION
def kfc_002(dll: BinaryIO, dll_path: str, dll_name: str, game_code: str, name: str, description: str, caution: str = None) -> UnionPatch | None:
    pe = pefile.PE(dll_path, fast_load=True)

    # Signature for instruction that sets J region
    setter_offset = find("89 05 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 33 CC E8 ?? ?? ?? ?? 48 83 C4 58 C3 B8 02 00 00 00", dll)
    if setter_offset is None: return None

    # skip two bytes, next 4 bytes (little endian) are rip relative address to our data
    dll.seek(setter_offset + 2)
    region_offset = struct.unpack("<i", dll.read(4))[0]

    # rip is already the next instruction
    region_address = pe.get_rva_from_offset(setter_offset + 6) + region_offset

    # Signature for our patch location
    offset = find("E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8D 48 ?? FF 15 ?? ?? ?? ?? 48 8B C8", dll)
    if offset is None: return None
    offset_rva = pe.get_rva_from_offset(offset)

    # Need rip to be pointed after the mov instruction, and there is a 5 byte and 6 byte instruction in our patch
    relative_address = region_address - (offset_rva + 5 + 6)
    address_string = struct.pack("<i", relative_address).hex().upper()

    # UNION OPTIONS
    dll.seek(offset)
    default  = UnionSubPatch("Default", offset, dll_name, dll.read(13).hex().upper())
    japan = UnionSubPatch("Japan (J)", offset, dll_name, "B8000000008905" + address_string + "9090")
    korea = UnionSubPatch("Korea (K)", offset, dll_name, "B8010000008905" + address_string + "9090")
    asia = UnionSubPatch("Asia (A)", offset, dll_name, "B8020000008905" + address_string + "9090")
    indonesia = UnionSubPatch("Indonesia (Y)", offset, dll_name, "B8030000008905" + address_string + "9090")
    america = UnionSubPatch("America (U)", offset, dll_name, "B8040000008905" + address_string + "9090")

    return UnionPatch(name, description, game_code, [ default, japan, korea, asia, indonesia, america ], caution)

# REROUTE 'FREE PLAY' TEXT
def ldj_001(dll: BinaryIO, dll_path: str, dll_name: str, game_code: str, name: str, description: str, caution: str = None) -> UnionPatch | None:
    pe = pefile.PE(dll_path, fast_load=True)

    # TICKER OFFSET
    ticker_offset = find("48 8D 0D ?? ?? ?? ?? 48 8B D3 FF 15 ?? ?? ?? ?? 48 8B 5C 24 ?? 33 C0 89 3D ?? ?? ?? ?? 48 83 C4 20 5F C3", dll, 8000000, 3)
    if ticker_offset is None: return None
    relative = pe.get_rva_from_offset(ticker_offset)
    dll.seek(ticker_offset)
    ticker_offset = struct.unpack("<i", dll.read(4))[0]
    absolute_ticker_offset = relative + ticker_offset

    # HIDDEN OFFSET
    hidden_offset = find("00 00 00 20 20 00 00", dll, 10000000, 3)
    if hidden_offset is None: return None
    hidden = pe.get_rva_from_offset(hidden_offset)

    # UNION OFFSET
    offset = find("48 83 EC 58 45 84 C0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8D 05", dll, 4500000, 31)
    if offset is None: return None

    # UNION OPTIONS
    dll.seek(offset)
    default = UnionSubPatch("Default", offset, dll_name, dll.read(4).hex().upper())
    ticker_info = UnionSubPatch("Song Title/Ticker information", offset, dll_name, struct.pack("<i", absolute_ticker_offset - pe.get_rva_from_offset(offset)).hex().upper())
    hide = UnionSubPatch("Hide", offset, dll_name, str(struct.pack("<i", hidden - pe.get_rva_from_offset(offset) - 4).hex().upper()))

    return UnionPatch(name, description, game_code, [ default, ticker_info, hide ], caution)

# Reroute PASELI: ****** Text To Song Title/Ticker Information
def ldj_002(dll: BinaryIO, dll_path: str, dll_name: str, game_code: str, name: str, description: str, caution: str = None) -> MemoryPatch | None:
    pe = pefile.PE(dll_path, fast_load=True)

    # TICKER OFFSET
    ticker_offset = find("48 8D 0D ?? ?? ?? ?? 48 8B D3 FF 15 ?? ?? ?? ?? 48 8B 5C 24 ?? 33 C0 89 3D ?? ?? ?? ?? 48 83 C4 20 5F C3", dll, 8000000, 3)
    if ticker_offset is None: return None
    relative = pe.get_rva_from_offset(ticker_offset)
    dll.seek(ticker_offset)
    ticker_offset = struct.unpack("<i", dll.read(4))[0]
    absolute_ticker_offset = relative + ticker_offset

    # MEMPATCH OFFSET
    offset = find("00 FF 15 ?? ?? ?? 00 EB 17 4C 8D 05 ?? ?? ?? 00 BA 00 01 00 00 48 8D", dll, 0, 12)
    if offset is None: return None

    # MEMPATCH OPTIONS
    dll.seek(offset)
    data_enabled = struct.pack("<i", absolute_ticker_offset - pe.get_rva_from_offset(offset)).hex().upper()
    data_disabled = dll.read(round(len(data_enabled) / 2)).hex().upper()

    subpatch = MemorySubPatch(offset, dll_name, data_disabled, data_enabled)
    return MemoryPatch(name, description, game_code, [ subpatch ], caution)

# TODO: Make main less nested and bloated, delegate functionality elsewhere, optimize where possible.
def main():
    # Load arguments, set logger
    args = parse_args()
    loglevel = getattr(logging, args.loglevel.upper(), logging.INFO)
    set_logger(loglevel)

    # Ensure required directories exists
    Path("./patches").mkdir(parents=False, exist_ok=True)
    Path("./signatures").mkdir(parents=False, exist_ok=True)
    Path("./dlls").mkdir(parents=False, exist_ok=True)

    # For all *-signatures.json files in the signatures directory
    for signatures_path in Path("signatures").glob("*-signatures.json"):
        # Load signatures json, set aside the header information and pop it out of the data
        with open(signatures_path, 'r') as f:
            data: json = json.load(f)
        header: json = data.pop(0)
        game_code: str = header['gameCode']
        dll_name: str = header['dllName']

        # Optional game argument to only generate patches for matching gameCodes
        if args.game != "ALL":
            if game_code != args.game.upper():
                logger.debug(f"Skipping '{game_code}'")
                continue

        logger.info(f"[{game_code}]")
        # For every .dll matching the name provided in the header
        for dll_path in Path("dlls").glob(dll_name.replace(".dll", "*.dll")):
            # Create value to store final patches, add header information to it
            game_patches = [json.dumps(
                {
                    "gameCode": game_code,
                    "version": f"? ({str(dll_path).replace("dlls\\", "")})",
                    "lastUpdated": datetime.datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                    "source": "https://sp2x.two-torial.xyz/"
                }, indent=4)]

            with open(dll_path, "r+b") as dll:
                logger.info(f"Processing '{dll.name}'")
                i = 0
                j = 0
                # For each entry (patch) in the json data
                for entry in data:
                    j += 1
                    # Extract patch info
                    entry_type = entry.get('type')
                    entry_name = entry.get('name')
                    entry_desc = entry.get('description')
                    entry_caution = entry.get('caution')
                    entry_subpatches = entry.get('patches')
                    # Check mandatory info for ALL types of patches is present, otherwise skip the patch entirely
                    if entry_type is None or entry_name is None or entry_desc is None:
                        continue

                    # Process patch based on type
                    match entry_type:
                        # Hardcoded patches
                        case "hardcoded":
                            patch_id = entry.get("id")
                            if patch_id is None:
                                continue
                            patch_id = patch_id.lower()

                            match patch_id:
                                case "kfc_001":
                                    patch = kfc_001(dll, dll_path, dll_name, game_code, entry_name, entry_desc, entry_caution)
                                case "kfc_002":
                                    patch = kfc_002(dll, dll_path, dll_name, game_code, entry_name, entry_desc, entry_caution)
                                case "ldj_001":
                                    patch = ldj_001(dll, dll_path, dll_name, game_code, entry_name, entry_desc, entry_caution)
                                case "ldj_002":
                                    patch = ldj_002(dll, dll_path, dll_name, game_code, entry_name, entry_desc, entry_caution)
                                case _:
                                    patch = None

                            if patch is not None:
                                game_patches.append(patch)
                                logger.debug(f"[{entry_type}] '{entry_name}' found ({patch_id})")
                                i += 1
                            else:
                                logger.warning(f"[{entry_type}] '{entry_name}' not found ({patch_id})")

                        # Memory patches
                        case "memory":
                            # If patches are not present, skip
                            if entry_subpatches is None:
                                continue
                            # Create a list to store memory subpatches
                            mem_subpatches: list[MemorySubPatch | list] = []
                            # For each subpatch
                            for subpatch in entry_subpatches:
                                # Extract its information, skip it if something mandatory isn't there 
                                spatch_start: int = subpatch.get("start", 0)
                                spatch_sig: str = subpatch.get("signature")
                                if spatch_sig is None:
                                    logger.error(f"[{entry_type}] '{entry_name}' is missing 'signature' in one of its subpatches.")
                                    continue
                                spatch_adjust: int = subpatch.get("adjust", 0)
                                spatch_data: str = subpatch.get("data")
                                if spatch_data is None:
                                    logger.error(f"[{entry_type}] '{entry_name}' is missing 'data' in one of its subpatches.")
                                    continue
                                patch_all: bool = subpatch.get("patchall", False)

                                # Find the offset inside the dll based on the information
                                offset: int = find(spatch_sig, dll, spatch_start, spatch_adjust)
                                # If an offset is found, create and store the subpatch
                                if offset is not None:
                                    dll.seek(offset)
                                    if spatch_data == "NUL":
                                        spatch_disabled = spatch_sig.replace(" ", "")
                                    else:
                                        spatch_disabled: str = dll.read(round(len(spatch_data.replace(" ", "")) / 2)).hex().upper()
                                    mem_subpatches.append(MemorySubPatch(offset, dll_name, spatch_disabled, spatch_data))

                                # Loop through the whole file to find all instances of the signature if patchall is true
                                while patch_all and offset is not None:
                                    offset = find(spatch_sig, dll, offset + 1, spatch_adjust)
                                    if offset is not None:
                                        dll.seek(offset)
                                        spatch_disabled: str = dll.read(round(len(spatch_data.replace(" ", "")) / 2)).hex().upper()
                                        mem_subpatches.append(MemorySubPatch(offset, dll_name, spatch_disabled, spatch_data))

                            # If EVERY patch for this entry have been found, proceed
                            if len(mem_subpatches) >= len(entry_subpatches):
                                game_patches.append(MemoryPatch(entry_name, entry_desc, game_code, mem_subpatches, entry_caution))
                                logger.debug(f"[{entry_type}] '{entry_name}' found ({len(mem_subpatches)}/{len(entry_subpatches)})")
                                i += 1
                            else:
                                logger.warning(f"[{entry_type}] '{entry_name}' not found ({len(mem_subpatches)}/{len(entry_subpatches)})")

                        # Union patches
                        case "union":
                            # If patches are not present, skip
                            if entry_subpatches is None:
                                continue

                            # Create a list to store memory subpatches
                            union_subpatches: list[UnionSubPatch | list] = []

                            # Extract extra patch info
                            patch_sig: str = entry.get("signature")
                            patch_start: int = entry.get("start", 0)
                            patch_adjust: int = entry.get("adjust", 0)

                            # Find the offset inside the dll based on the information
                            offset: int = find(patch_sig, dll, patch_start, patch_adjust)
                            if offset is None:
                                logger.error(f"[{entry_type}] '{entry_name}' offset not found.")
                                continue

                            # Find the default value based on the signature and adjust values
                            dll.seek(offset + patch_adjust)

                            # Check every non-default option is the same length, and extract it
                            option_length: int | None = None
                            same_length: bool = True
                            for subpatch in entry_subpatches:
                                spatch_data = subpatch.get("data")
                                if spatch_data.lower() == "default":
                                    continue
                                length = round(len(spatch_data.replace(" ", "")) / 2)
                                if option_length is not None and length != option_length:
                                    same_length = False
                                    break
                                option_length = length
                            if not same_length or option_length is None:
                                logger.error(f"[{entry_type}] '{entry_name}' has unequal data lengths.")
                                continue

                            # For each subpatch
                            for subpatch in entry_subpatches:
                                # Extract its information
                                spatch_name: str = subpatch.get("name")
                                if spatch_name is None:
                                    logger.error(f"[{entry_type}] '{entry_name}' is missing 'name' in one of its subpatches.")
                                    continue
                                spatch_name = spatch_name.replace(" (Default)", "")

                                spatch_data = subpatch.get("data")
                                if spatch_data is None:
                                    logger.error(f"[{entry_type}] '{entry_name}' is missing 'data' in one of its subpatches.")
                                    continue
                                if spatch_data.lower() == "default":
                                    if spatch_name != "Default":
                                        spatch_name = f"{spatch_name} (Default)"
                                    dll.seek(offset)
                                    spatch_data = dll.read(option_length).hex().upper()

                                union_subpatches.append(UnionSubPatch(spatch_name, offset, dll_name, spatch_data))

                            # If we have found the signature (in the default option), and all non-default options have been parsed, proceed
                            if len(union_subpatches) == len(entry_subpatches):
                                game_patches.append(UnionPatch(entry_name, entry_desc, game_code, union_subpatches, entry_caution))
                                logger.debug(f"[{entry_type}] '{entry_name}' found ({len(union_subpatches)}/{len(entry_subpatches)})")
                                i += 1
                            else:
                                logger.warning(f"[{entry_type}] '{entry_name}' not found ({len(union_subpatches)}/{len(entry_subpatches)})")

                        # Number patches
                        case "number":
                            # Get patch, skip if not present
                            num_patch = entry.get('patch')
                            if num_patch is None:
                                continue

                            # Extract patch information, skip if something mandatory isn't there
                            patch_start = num_patch.get("start", 0)
                            patch_sig = num_patch.get("signature")
                            patch_adjust = num_patch.get("adjust", 0)
                            patch_size = num_patch.get("size")
                            patch_min = num_patch.get("min")
                            patch_max = num_patch.get("max")
                            if spatch_sig is None or patch_size is None or patch_min is None or patch_max is None:
                                continue

                            offset = find(patch_sig, dll, patch_start, patch_adjust)
                            if offset is not None:
                                game_patches.append(NumberPatch(entry_name, entry_desc, game_code, dll_name, offset, patch_size, patch_min, patch_max, entry_caution))
                                logger.debug(f"[{entry_type}] '{entry_name}' found")
                                i += 1
                            else:
                                logger.warning(f"[{entry_type}] '{entry_name}' not found")

                        # Unknown
                        case _:
                            logger.error(f"Unknown entry type for '{entry_name}'")
                            continue

                # Write to file
                new_file_str = f"./patches/{get_identifier(game_code, dll)}"
                #if i < j:
                    #new_file_str += "_incomplete"
                new_file_str += ".json"
                new_file = Path(new_file_str)
                new_data = [json.loads(str(patch)) for patch in game_patches]
                try:
                    with open(new_file, "w", encoding='utf-8') as f:
                        writer = io.StringIO()
                        json.dump(new_data, writer, indent=4)
                        writer.seek(0)
                        f.write(writer.getvalue())
                except Exception as e:
                    logger.fatal(f"Error writing file: {e}")
                    raise

                # Log results
                logger.info(f"-> {new_file} ({i}/{j})")


if __name__ == "__main__":
    main()