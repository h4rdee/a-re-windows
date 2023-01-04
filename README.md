# A-RE Windows
Windows applications analysis utility <br> (pretty simple at the moment, but who knows whats coming up next..) <br>

## Current features:
- Retrieving basic sample information, such as `compiler info`, `packer info`, `installer info`
- Detecting sample capabilities based on large collection of yara rules
- Custom yara checker for testing your own yara rules
- Cross-platform user-friendly UI powered by Tkinter!

## Credits:
- [RetDec](https://github.com/avast/retdec) for providing yara rules
- [Yara-Rules](https://github.com/Yara-Rules/rules) for providing yara rules
- [PETools](https://github.com/petoolse/petools) for signatures that i generated some yara rules from
- [horsicq](https://github.com/horsicq/Detect-It-Easy) for signatures from Detect It Easy based on which i generated some yara rules as well
- [rdbende](https://gitlab.com/rdbende/chlorophyll) for tkinter `chlorophyll` add-on
- [erocarrera](https://github.com/erocarrera/pefile) for `pefile` library
- [elceef](https://github.com/elceef/ppdeep/blob/master/ppdeep.py) for pure python ssdeep hashing implementation (`ppdeep` library)

## Notes:
This project was made by me, and my python knowledge kinda sucks <br>
Don't expect to see quality code here (PR's are welcomed!) <br>
I'm working on this project at spare time, which means that no regular support of this tool will be provided

## Screenshots:
![image](https://user-images.githubusercontent.com/37783231/210627706-8db35c2b-e29a-4c9d-a73d-adb7981cde1b.png)
![image](https://user-images.githubusercontent.com/37783231/210627188-c05b8ddc-333f-4a7d-9840-b02021420db2.png)
![image](https://user-images.githubusercontent.com/37783231/210627546-a1af6fe4-55bf-4155-947e-47f11de632de.png)
![image](https://user-images.githubusercontent.com/37783231/207005415-9b23c043-3883-4e51-80f0-5664d92c5307.png)
