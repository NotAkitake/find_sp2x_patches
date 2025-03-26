import argparse
from datetime import datetime, timezone
import json
import logging
from typing import BinaryIO
from venv import logger
import pefile
import re
import struct
from pathlib import Path

class BasePatch:
    def __init__(self, name: str, description: str, game_code: str, caution: str = None):
        self.name = name
        self.description = description
        self.game_code = game_code
        self.caution = caution

    def to_dict(self) -> dict:
        base_dict = {
            "name": self.name,
            "description": self.description,
            "caution": self.caution,
            "gameCode": self.game_code
        }
        return {k: v for k, v in base_dict.items() if v is not None}

    def __str__(self):
        return json.dumps(self.to_dict(), indent=4)
    

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


class MemoryPatch(BasePatch):
    def __init__(self, name: str, description: str, game_code: str, patches: list[MemorySubPatch], caution: str = None):
        super().__init__(name, description, game_code, caution)
        self.patches = patches

    def to_dict(self) -> dict:
        patch_dict = super().to_dict()
        patch_dict.update({
            "type": "memory",
            "patches": [p.to_dict() for p in self.patches]
        })
        return patch_dict


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


class UnionPatch(BasePatch):
    def __init__(self, name: str, description: str, game_code: str, patches: list[UnionSubPatch], caution: str = None):
        super().__init__(name, description, game_code, caution)
        self.patches = patches

    def to_dict(self) -> dict:
        patch_dict = super().to_dict()
        patch_dict.update({
            "type": "union",
            "patches": [p.to_dict() for p in self.patches]
        })
        return patch_dict


class NumberPatch(BasePatch):
    def __init__(self, name: str, description: str, game_code: str, dll_name: str, offset: int, size: int, i_min: int, i_max: int, caution: str = None):
        super().__init__(name, description, game_code, caution)
        self.dll_name = dll_name
        self.offset = offset
        self.size = size
        self.i_min = i_min
        self.i_max = i_max

    def to_dict(self) -> dict:
        patch_dict = super().to_dict()
        patch_dict.update({
            "type": "number",
            "patch": {
                "dllName": self.dll_name,
                "offset": self.offset,
                "size": self.size,
                "min": self.i_min,
                "max": self.i_max
            }
        })
        return patch_dict


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


def find(signature: str, dll: BinaryIO, start_offset: int = 0, adjust: int = 0) -> int | None:
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


def get_identifier(game_code: str, dll_path: str) -> str:
    """
    Concatenates 'game_code' with the PE identifier for 'dll'.
    :param game_code: Game code for the dll (KFC, LDJ, M39, ...).
    :param dll: Dll file opened in binary mode.
    :return: Identifier for the dll.
    """
    try:
        with open(dll_path, 'rb') as dll:
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

# Force Unlock All Backgrounds
def l44_001(dll: BinaryIO, dll_path: str, dll_name: str, game_code: str, name: str, description: str, caution: str = None) -> MemoryPatch | None:
    pe = pefile.PE(dll_path, fast_load=True)

    # 1
    offset = find("75 43 0F 28 85 B0 FD FF FF", dll, 1000000)
    if offset is None: return None
    subpatch1 = MemorySubPatch(offset, dll_name, "75", "EB")

    # 2
    offset = find("0F B7 45 B0 89 04 CD", dll, 1000000)
    if offset is None: return None
    subpatch2 = MemorySubPatch(offset, dll_name, "0F B7 45 B0", "31 C0 90 90")

    # 3
    # FUNCTION OFFSET
    offset = find("55 8B EC 83 E4 F0 81 EC 98 01 00 00", dll, 1000000)
    if offset is None: return None
    dll.seek(offset)
    offset = find("75 ?? 0F 28 44", dll, offset+1)
    if offset is None: return None
    offset = find("75 ?? 0F 28 44", dll, offset+1)
    if offset is None: return None
    subpatch3 = MemorySubPatch(offset, dll_name, "75", "EB")

    return MemoryPatch(name, description, game_code, [ subpatch1, subpatch2, subpatch3 ], caution)

class PatchProcessor:
    def __init__(self, dll: BinaryIO, dll_path: str, dll_name: str, game_code: str):
        self.dll = dll
        self.dll_path = dll_path
        self.dll_name = dll_name
        self.game_code = game_code
        self.pe = pefile.PE(dll_path, fast_load=True)

    def process_patch(self, entry: dict) -> BasePatch | None:
        processors = {
            "hardcoded": self._process_hardcoded,
            "memory": self._process_memory,
            "union": self._process_union,
            "number": self._process_number
        }
        
        patch_type = entry.get('type')
        processor = processors.get(patch_type)
        if not processor:
            logger.error(f"Unknown entry type for '{entry.get('name')}'")
            return None
            
        return processor(entry)

    def _process_memory(self, entry: dict) -> MemoryPatch | None:
        entry_subpatches = entry.get('patches')
        if not entry_subpatches:
            return None

        mem_subpatches: list[MemorySubPatch] = []
        
        for subpatch in entry_subpatches:
            spatch_sig = subpatch.get("signature")
            spatch_data = subpatch.get("data")
            if not spatch_sig or spatch_data is None:
                logger.error(f"[memory] '{entry.get('name')}' is missing required fields in subpatch")
                continue

            offset = find(spatch_sig, self.dll, subpatch.get("start", 0), subpatch.get("adjust", 0))
            if offset is None:
                logger.warning(f"[memory] Signature '{spatch_sig}' not found for '{entry.get('name')}'")
                continue

            self.dll.seek(offset)
            if spatch_data == "NUL":
                spatch_disabled = spatch_sig.replace(" ", "")
            else:
                spatch_disabled = self.dll.read(round(len(spatch_data.replace(" ", "")) / 2)).hex().upper()
            
            mem_subpatches.append(MemorySubPatch(offset, self.dll_name, spatch_disabled, spatch_data))

            if subpatch.get("patchall", False):
                while True:
                    offset = find(spatch_sig, self.dll, offset + 1, subpatch.get("adjust", 0))
                    if offset is None:
                        break
                    self.dll.seek(offset)
                    spatch_disabled = self.dll.read(round(len(spatch_data.replace(" ", "")) / 2)).hex().upper()
                    mem_subpatches.append(MemorySubPatch(offset, self.dll_name, spatch_disabled, spatch_data))

        if len(mem_subpatches) >= len(entry_subpatches):
            return MemoryPatch(entry.get('name'), entry.get('description'), 
                              self.game_code, mem_subpatches, entry.get('caution'))
        return None

    def _process_hardcoded(self, entry: dict) -> MemoryPatch | UnionPatch | None:
        """Process a hardcoded patch entry and return the appropriate patch object."""
        patch_id = entry.get("id")
        if patch_id is None:
            return None
        
        patch_funcs = {
            "kfc_001": kfc_001,
            "kfc_002": kfc_002,
            "ldj_001": ldj_001,
            "ldj_002": ldj_002,
            "l44_001": l44_001
        }
        
        patch_func = patch_funcs.get(patch_id.lower())
        if patch_func is None:
            return None
        
        return patch_func(self.dll, self.dll_path, self.dll_name, self.game_code, entry.get('name'), 
                         entry.get('description'), entry.get('caution'))

    def _process_union(self, entry: dict) -> UnionPatch | None:
        """Process a union patch entry and return a UnionPatch object if successful."""
        entry_subpatches = entry.get('patches')
        if not entry_subpatches:
            return None

        offset = find(entry.get("signature", ""), self.dll, 
                     entry.get("start", 0), entry.get("adjust", 0))
        if offset is None:
            return None

        # Validate patch lengths
        option_length = None
        for subpatch in entry_subpatches:
            spatch_data = subpatch.get("data", "")
            if spatch_data.lower() == "default":
                continue
            length = round(len(spatch_data.replace(" ", "")) / 2)
            if option_length and length != option_length:
                return None
            option_length = length

        union_subpatches = []
        for subpatch in entry_subpatches:
            spatch_name = subpatch.get("name")
            spatch_data = subpatch.get("data")
            if not spatch_name or spatch_data is None:
                continue

            if spatch_data.lower() == "default":
                if spatch_name != "Default":
                    spatch_name = f"{spatch_name} (Default)"
                self.dll.seek(offset)
                spatch_data = self.dll.read(option_length).hex().upper()

            union_subpatches.append(UnionSubPatch(spatch_name, offset, self.dll_name, spatch_data))

        if len(union_subpatches) == len(entry_subpatches):
            return UnionPatch(entry.get('name'), entry.get('description'), 
                             self.game_code, union_subpatches, entry.get('caution'))
        return None

    def _process_number(self, entry: dict) -> NumberPatch | None:
        """Process a number patch entry and return a NumberPatch object if successful."""
        num_patch = entry.get('patch')
        if not num_patch:
            return None

        required = ["signature", "size", "min", "max"]
        missing = [field for field in required if field not in num_patch or num_patch[field] is None]
        if missing:
            return None

        offset = find(num_patch["signature"], self.dll, 
                     num_patch.get("start", 0), num_patch.get("adjust", 0))
        if offset is None:
            return None

        return NumberPatch(entry.get('name'), entry.get('description'), self.game_code,
                          self.dll_name, offset, num_patch["size"], num_patch["min"], 
                          num_patch["max"], entry.get('caution'))

def process_dll_patches(dll_path: Path, game_code: str, dll_name: str, patch_data: list) -> list:
    patches = [
        json.dumps(
            {
                "gameCode": game_code,
                "version": f"? ({str(dll_path).replace("dlls\\", "")})",
                "lastUpdated": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                "source": "https://sp2x.two-torial.xyz/"
            }, indent=4)
    ]
    successful = 0
    total = 0

    with open(dll_path, "r+b") as dll:
        logger.info(f"Processing '{dll.name}'")
        processor = PatchProcessor(dll, dll_path, dll_name, game_code)
        
        for entry in patch_data:
            total += 1
            if patch := processor.process_patch(entry):
                patches.append(patch)
                successful += 1
                logger.debug(f"[{entry['type']}] '{entry['name']}' found")
            else:
                logger.warning(f"[{entry['type']}] '{entry['name']}' not found")

    # Write results to file
    identifier = get_identifier(game_code, dll_path)
    output_path = Path(f"./patches/{identifier}.json")
        
    try:
        with open(output_path, "w", encoding='utf-8') as f:
            json.dump([json.loads(str(p)) for p in patches], f, indent=4)
            logger.info(f"-> '{output_path}' ({successful}/{total})")
    except Exception as e:
        logger.fatal(f"Error writing file: {e}")
        raise

    return patches

def main():
    args = parse_args()
    loglevel = getattr(logging, args.loglevel.upper(), logging.INFO)
    set_logger(loglevel)

    Path("./patches").mkdir(parents=False, exist_ok=True)
    Path("./signatures").mkdir(parents=False, exist_ok=True)
    Path("./dlls").mkdir(parents=False, exist_ok=True)

    for signatures_path in Path("signatures").glob("*-signatures.json"):
        with open(signatures_path, 'r') as f:
            data = json.load(f)
        
        header = data.pop(0)
        game_code = header['gameCode']
        dll_name = header['dllName']

        if args.game != "ALL" and game_code != args.game.upper():
            logger.debug(f"Skipping '{game_code}'")
            continue

        logger.info(f"[{game_code}]")
        for dll_path in Path("dlls").rglob(dll_name.replace(".dll", "*.dll")):
            patches = process_dll_patches(dll_path, game_code, dll_name, data)

if __name__ == "__main__":
    main()