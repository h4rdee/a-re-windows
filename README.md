# A-RE Windows
Windows applications analysis utility <br> (pretty simple at the moment, but who knows whats coming up next..) <br>

## Current features:
- Retrieving basic sample information, such as **compiler info**, **packer info**, **installer info**
- Obtaining info about PE **rich signature**
- Detecting sample **capabilities** based on large collection of yara rules
- Checking sample against vendor **signatures** (Detect It Easy, PE Tools, etc)
- Inspecting PE **sections**, dumping them, checking their entropy
- Gathering various info about PE **imports** and **exports**
- **Hashing** a sample (sha256, sha1, md5, imphash, ssdeep, rich header hash, etc)
* .NET samples support
  - Parsing strings from `Strings` heap
  - Parsing strings from `UserStrings` heap
- Custom **yara checker** for testing your own yara rules
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
- [elceef](https://github.com/elceef/ppdeep/blob/master/ppdeep.py) for pure python ssdeep hashing implementation (`ppdeep` library)

## Notes:
This project was made by me, and my python knowledge kinda sucks <br>
Don't expect to see quality code here (PR's are welcomed!) <br>
I'm working on this project at spare time, which means that no regular support of this tool will be provided

## Screenshots:
<img src="https://user-images.githubusercontent.com/37783231/211074437-d4baa9c6-9003-4a74-914c-8415b768f588.png" width="700" height="450">
<img src="https://user-images.githubusercontent.com/37783231/211195836-5fc88387-363c-4ea3-8487-5c553d569d33.png" width="700" height="450">
<img src="https://user-images.githubusercontent.com/37783231/211195815-86977e12-abfb-4240-898f-87c6710ef239.png" width="700" height="450">
<img src="https://user-images.githubusercontent.com/37783231/211195736-314effed-c437-4d42-92dc-cf9916c93232.png" width="700" height="450">
<img src="https://user-images.githubusercontent.com/37783231/211195698-30870937-0d21-4b9f-be1d-5850107abff5.png" width="700" height="450">
<img src="https://user-images.githubusercontent.com/37783231/211195513-6ccc6b27-bce0-4344-b215-8cb19ba41ea7.png" width="700" height="450">
<img src="https://user-images.githubusercontent.com/37783231/211195955-f6a13216-5143-4d97-ad12-2d9c0246ab14.png" width="700" height="450">
