# find_sp2x_patches

## About

- `find_sp2x_patches.py` finds as many Spice2x patches as possible for various game versions.
- `find_all_occurences.py` is a helper script to quickly test run a signature search for a specific DLL.

**Notes**: 
1. The provided **signatures will break over time**, I will however do my best to keep updating them as time goes on.
2. The provided **signatures are built for the bleeding edge of n-0**, don't expect them to work for older content.
3. Documentation on how to create the signatures files **will come soon**. In the meantime you should be able to figure it out by reading their format.

## Requirements

- **Python 3**

## Directories

- `dlls` Contains game's .dll files you want to find patches for.
- `patches` Is the output folder for spice2x-compatible .json files.
- `signatures` Contains `<gamecode>-signatures.json` files used by the script to determine patches.

## Usage

`python find_sp2x_patches.py [-h] [--game GAME] [--loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}]`

### Arguments
*All arguments are optional*
- `-h` Prints out a help message similar to this
- `--game` Set a specific game to run the script for (example: KFC, default: ALL)

If `--game` is unset or set to `ALL`, the script will run for all signatures files in the `signatures` directory.  
If `--game` is set, for example `--game LDJ`, the script will run for the matching `LDJ-signatures.json` only.  
The script will attempt to find patches for all corresponding dll files inside the `dlls` directory.

- `--loglevel` Set the console logging level (default: INFO)

Logs are sent to the console AND to a `logs.txt` file.  
The console will only show INFO and above messages by default, but this argument lets you change that.  
`logs.txt` logs everything, even DEBUG messages regardless of the set loglevel.  
`logs.txt` gets overwritten on every run.

Spice2x-compatible patches.json files are outputted to the `patches` directory.

### Examples

#### File tree
> find_sp2x_patches/  
> ├─ dlls/  
> ├─── bm2dx31_012-0826.dll  
> ├─── bm2dx32_012-1009.dll  
> ├─── soundvoltex-1022.dll  
> ├─ patches/  
> ├─ signatures/  
> ├─── KFC-signatures.json  
> ├─── LDJ-signatures.json  
> ├─ find_sp2x_patches.py  

#### Commands and Output

*Note: The patches marked as not found in this first example are expected.  
The signature file is the same for both LDJ-010 and LDJ-012 dlls, and these are LDJ-010 only patches.*

**1.**

```pwsh
> python find_sp2x_patches.py 
2024-10-27 16:44:39,245 - INFO: [KFC]
2024-10-27 16:44:39,245 - INFO: Processing 'dlls\soundvoltex-1022.dll'
2024-10-27 16:44:39,801 - INFO: -> patches\KFC-67108c5c_6d2ec8.json (15/15)
2024-10-27 16:44:39,802 - INFO: [LDJ]
2024-10-27 16:44:39,802 - INFO: Processing 'dlls\bm2dx31_012-0826.dll'
2024-10-27 16:44:40,153 - WARNING: [memory] 'Force LDJ Mode' not found (0/1)
2024-10-27 16:44:40,942 - WARNING: [memory] 'Force LDJ Software Video Decoder' not found (0/1)
2024-10-27 16:44:41,076 - INFO: -> patches\LDJ-66c58ff1_9b323c.json (32/34)
2024-10-27 16:44:41,076 - INFO: Processing 'dlls\bm2dx32_012-1009.dll'
2024-10-27 16:44:41,217 - WARNING: [memory] 'Force LDJ Mode' not found (0/1)
2024-10-27 16:44:42,070 - WARNING: [memory] 'Force LDJ Software Video Decoder' not found (0/1)
2024-10-27 16:44:42,212 - INFO: -> patches\LDJ-66ff5733_a6589c.json (32/34)
```

**2.**

```pwsh
2.
> python .\find_sp2x_patches.py --game KFC --loglevel DEBUG
2024-10-27 16:45:41,985 - INFO: [KFC]
2024-10-27 16:45:41,986 - INFO: Processing 'dlls\soundvoltex-1022.dll'
2024-10-27 16:45:41,992 - DEBUG: [union] 'Game FPS Target' found (2/2)
2024-10-27 16:45:42,017 - DEBUG: [union] 'Note FPS Target' found (2/2)
2024-10-27 16:45:42,032 - DEBUG: [memory] 'Shared mode WASAPI' found (1/1)
2024-10-27 16:45:42,047 - DEBUG: [memory] 'Shared mode WASAPI Valkyrie' found (1/1)
2024-10-27 16:45:42,167 - DEBUG: [hardcoded] 'Hide premium guide banner' found (kfc_001)
2024-10-27 16:45:42,258 - DEBUG: [memory] 'Hide all bottom text' found (12/12)
2024-10-27 16:45:42,286 - DEBUG: [memory] 'Standard/Menu Timer Freeze' found (1/1)
2024-10-27 16:45:42,342 - DEBUG: [memory] 'Premium Free Timer Freeze' found (3/3)
2024-10-27 16:45:42,358 - DEBUG: [union] 'Premium Time Length' found (14/14)
2024-10-27 16:45:42,374 - DEBUG: [memory] 'ASIO 2 Channels Mode' found (1/1)
2024-10-27 16:45:42,391 - DEBUG: [memory] 'Disable power change' found (1/1)
2024-10-27 16:45:42,411 - DEBUG: [memory] 'Disable monitor change' found (1/1)
2024-10-27 16:45:42,425 - DEBUG: [memory] 'Disable Subscreen in Valkyrie mode' found (1/1)
2024-10-27 16:45:42,513 - DEBUG: [memory] 'Valkyrie Mode 60Hz' found (3/3)
2024-10-27 16:45:42,549 - DEBUG: [memory] 'Force BIO2 (KFC) IO in Valkyrie mode' found (1/1)
2024-10-27 16:45:42,550 - INFO: -> patches\KFC-67108c5c_6d2ec8.json (15/15)
2024-10-27 16:45:42,551 - DEBUG: Skipping 'LDJ'
```
