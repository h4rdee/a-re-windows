# A-RE Windows
Windows applications analysis utility <br> (pretty simple at the moment, but who knows whats coming up next..) <br>

## Current features:
- Retrieving basic sample information, such as **compiler info**, **packer info**, **installer info**
- Obtaining info about PE **rich signature**
- Detecting sample **capabilities** based on large collection of yara rules
- Checking sample against vendor **signatures** (Detect It Easy, PE Tools, etc)
- Inspecting PE **sections**, dumping them, checking their entropy
- Gathering various info about PE **imports**
- **Hashing** a sample (sha256, sha1, md5, imphash, ssdeep, rich header hash, etc)
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
- [elceef](https://github.com/elceef/ppdeep/blob/master/ppdeep.py) for pure python ssdeep hashing implementation (`ppdeep` library)

## Notes:
This project was made by me, and my python knowledge kinda sucks <br>
Don't expect to see quality code here (PR's are welcomed!) <br>
I'm working on this project at spare time, which means that no regular support of this tool will be provided

## Screenshots:
![image](https://user-images.githubusercontent.com/37783231/211074437-d4baa9c6-9003-4a74-914c-8415b768f588.png)
![image](https://user-images.githubusercontent.com/37783231/210627706-8db35c2b-e29a-4c9d-a73d-adb7981cde1b.png)
![image](https://user-images.githubusercontent.com/37783231/210627188-c05b8ddc-333f-4a7d-9840-b02021420db2.png)
![image](https://user-images.githubusercontent.com/37783231/210823785-386faf5f-b3b7-404d-885b-f47cef4d6f25.png)
![image](https://user-images.githubusercontent.com/37783231/210627546-a1af6fe4-55bf-4155-947e-47f11de632de.png)
![image](https://user-images.githubusercontent.com/37783231/211060840-0a2b1aa5-fedc-457e-8639-d4e95c7d72c8.png)
![image](https://user-images.githubusercontent.com/37783231/207005415-9b23c043-3883-4e51-80f0-5664d92c5307.png)
