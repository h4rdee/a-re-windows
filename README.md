# A-RE Windows
Windows applications analysis utility <br> (pretty simple at the moment, but who knows whats coming up next..) <br>

## Current features:
- Retrieving basic sample information, such as **compiler info**, **packer info**, **installer info**
- Obtaining info about PE **rich signature**
- Detecting sample **capabilities** based on large collection of yara rules
- Checking sample against vendor **signatures** (Detect It Easy, PE Tools, etc)
- Inspecting PE **sections**, dumping them, checking their entropy
- Gathering various info about PE **imports**, **exports** and **resources**
- Parsing **overlay** info
- **Hashing** a sample (sha256, sha1, md5, imphash, ~~ssdeep~~, rich header hash, etc)
* .NET samples support
  - Parsing strings from `Strings` heap
  - Parsing strings from `UserStrings` heap
  - Parsing guids from `Guid` heap
  - Parsing metadata tables (WIP)
- Custom **yara checker** for testing your own yara rules
- Extendable by **plugins**
- Cross-platform **user-friendly** UI powered by Tkinter!

## Credits:
- [VirusTotal](https://github.com/VirusTotal/yara-python) for `yara` ❤️
- [RetDec](https://github.com/avast/retdec) for providing yara rules
- [Yara-Rules](https://github.com/Yara-Rules/rules) for providing yara rules
- [PETools](https://github.com/petoolse/petools) for signatures that i generated some yara rules from
- [horsicq](https://github.com/horsicq/Detect-It-Easy) for signatures from Detect It Easy based on which i generated some yara rules as well
- [Adam](https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/) for PE sections names info
- [dishather](https://github.com/dishather/richprint/) for PE rich header comp.id database
- [rdbende](https://gitlab.com/rdbende/chlorophyll) for tkinter `chlorophyll` add-on
- [ragardner](https://github.com/ragardner/tksheet) for tkinter `tksheet` add-on
- [erocarrera](https://github.com/erocarrera/pefile) for `pefile` library
- [malwarefrank](https://github.com/malwarefrank/dnfile) for `dnfile` library
- [romainthomas](https://github.com/lief-project/LIEF) for `lief` library
- [elceef](https://github.com/elceef/ppdeep/blob/master/ppdeep.py) for pure python ssdeep hashing implementation (`ppdeep` library)

## Notes:
This project was made by me, and my python knowledge kinda sucks <br>
Don't expect to see quality code here (PR's are welcomed!) <br>
I'm working on this project at spare time, which means that no regular support of this tool will be provided

## Preview:
<img src="https://user-images.githubusercontent.com/37783231/212688002-e08daa32-b362-4e9b-9207-6ca571c9cf83.gif" width="700" height="450">
