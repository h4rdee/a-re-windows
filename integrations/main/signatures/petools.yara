// Signatures for PE Tools v1.5/PE Sniffer
// Authors: NEOx <neox@pisem.net>, .Cryorb <cryorb@tut.by> 
// Tnx: BiDark, dyn!o, Mike, DeMoNiX, FEUERRADER, Boris, seeq, Aster!x, aragon, Hellsp@wN, GPcH, ...
// Copyright [c] 2005 uinC Team 

// Converted to YARA rules for A-RE Windows by hardee

rule Borland_Pascal_v70_for_Windows
{
    meta:
        description = "Borland Pascal v7.0 for Windows"

    strings:
        $pattern = { 9A FF FF 00 00 9A FF FF 00 00 55 89 E5 31 C0 9A FF FF 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Borland_Cpp_for_Win32_1994
{
    meta:
        description = "Borland C++ for Win32 1994"

    strings:
        $pattern = { A1 ?? ?? ?? ?? C1 ?? ?? A3 ?? ?? ?? ?? 83 ?? ?? ?? ?? 75 ?? 57 51 33 C0 BF }
        $pattern_1 = { A1 ?? ?? ?? ?? C1 E0 02 A3 ?? ?? ?? ?? 57 51 33 C0 BF ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B CF 76 05 2B CF FC F3 AA 59 5F }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Borland_Cpp_for_Win32_1995
{
    meta:
        description = "Borland C++ for Win32 1995"

    strings:
        $pattern = { A1 ?? ?? ?? ?? C1 ?? ?? A3 ?? ?? ?? ?? 57 51 33 C0 BF ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B CF 76 }
        $pattern_1 = { A1 ?? ?? ?? ?? C1 ?? ?? A3 ?? ?? ?? ?? 83 ?? ?? ?? ?? 75 ?? 80 ?? ?? ?? ?? ?? ?? 74 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Borland_Cpp_for_Win32_1999
{
    meta:
        description = "Borland C++ for Win32 1999"

    strings:
        $pattern = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 ?? ?? ?? ?? A1 ?? ?? ?? ?? C1 E0 02 A3 ?? ?? ?? ?? 52 }
        $pattern_1 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Borland_Cpp_DLL
{
    meta:
        description = "Borland C++ DLL"

    strings:
        $pattern = { A1 ?? ?? ?? ?? C1 E0 02 A3 }
        $pattern_1 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 }
        $pattern_2 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 A1 C1 E0 02 A3 8B }
        $pattern_3 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 ?? ?? ?? ?? A1 ?? ?? ?? ?? C1 E0 02 A3 ?? ?? ?? ?? 8B }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Borland_Delphi_vxx_Component
{
    meta:
        description = "Borland Delphi vx.x (Component)"

    strings:
        $pattern = { C3 E9 ?? ?? ?? FF 8D 40 }
        $pattern_1 = { 55 8B EC 83 C4 F4 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Borland_Delphi_DLL
{
    meta:
        description = "Borland Delphi DLL"

    strings:
        $pattern = { 55 8B EC 83 C4 B4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 40 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Borland_Delphi_v60___v70
{
    meta:
        description = "Borland Delphi v6.0 - v7.0"

    strings:
        $pattern = { 55 8B EC 83 C4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $pattern_1 = { BA ?? ?? ?? ?? 83 7D 0C 01 75 ?? 50 52 C6 05 ?? ?? ?? ?? ?? 8B 4D 08 89 0D ?? ?? ?? ?? 89 4A 04 }
        $pattern_2 = { 53 8B D8 33 C0 A3 0? ?? ?? ?0 6A 00 E8 0? ?? ?0 FF A3 0? ?? ?? ?0 A1 0? ?? ?? ?0 A3 0? ?? ?? ?0 33 C0 A3 0? ?? ?? ?0 33 C0 A3 0? ?? ?? ?0 E8 }
        $pattern_3 = { 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 ?? ?? FB FF A1 ?? ?? ?? ?? 8B ?? E8 ?? ?? FF FF 8B 0D ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 00 8B 15 ?? ?? ?? ?? E8 ?? ?? FF FF A1 ?? ?? ?? ?? 8B ?? E8 ?? ?? FF FF E8 ?? ?? FB FF 8D 40 }
        $pattern_4 = { 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? FF A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? E8 }
        $pattern_5 = { 55 8B EC 83 C4 F0 B8 ?? ?? 45 00 E8 ?? ?? ?? FF A1 ?? ?? 45 00 8B 00 E8 ?? ?? FF FF 8B 0D }
        $pattern_6 = { 55 8B EC 83 C4 F0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Borland_Delphi_v20
{
    meta:
        description = "Borland Delphi v2.0"

    strings:
        $pattern = { E8 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 0A ?? ?? ?? B8 ?? ?? ?? ?? C3 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Borland_Delphi_v30
{
    meta:
        description = "Borland Delphi v3.0"

    strings:
        $pattern = { 50 6A ?? E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 55 8B EC 33 C0 }
        $pattern_1 = { 55 8B EC 83 C4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Borland_Delphi_v40___v50
{
    meta:
        description = "Borland Delphi v4.0 - v5.0"

    strings:
        $pattern = { 50 6A ?? E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 C7 42 08 ?? ?? ?? ?? C7 42 0C ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 }
        $pattern_1 = { 55 8B EC 83 C4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 }
        $pattern_2 = { 50 6A 00 E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 C7 42 08 00 00 00 00 C7 42 0C 00 00 00 00 E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Borland_Delphi_v50_KOL_MCK
{
    meta:
        description = "Borland Delphi v5.0 KOL/MCK"

    strings:
        $pattern = { 55 8B EC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? 00 00 00 }
        $pattern_1 = { 55 8B EC 83 C4 F0 B8 ?? ?? 40 00 E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF 8B C0 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Borland_Delphi_v60_KOL
{
    meta:
        description = "Borland Delphi v6.0 KOL"

    strings:
        $pattern = { 55 8B EC 83 C4 F0 B8 ?? ?? 40 00 E8 ?? ?? FF FF A1 ?? 72 40 00 33 D2 E8 ?? ?? FF FF A1 ?? 72 40 00 8B 00 83 C0 14 E8 ?? ?? FF FF E8 ?? ?? FF FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Borland_Delphi_Setup_Module
{
    meta:
        description = "Borland Delphi Setup Module"

    strings:
        $pattern = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Borland_Delphi_Component
{
    meta:
        description = "Borland Delphi (Component)"

    strings:
        $pattern = { C3 E9 ?? ?? ?? FF 8D 40 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Cygwin32
{
    meta:
        description = "Cygwin32"

    strings:
        $pattern = { 55 89 E5 83 EC 04 83 3D }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Dev_Cpp_v4
{
    meta:
        description = "Dev-C++ v4"

    strings:
        $pattern = { 55 89 E5 83 EC 08 83 C4 F4 6A ?? A1 ?? ?? ?? 00 FF D0 E8 ?? FF FF FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Dev_Cpp_v5
{
    meta:
        description = "Dev-C++ v5"

    strings:
        $pattern = { 55 89 E5 83 EC 14 6A ?? FF 15 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule FASM_v13x
{
    meta:
        description = "FASM v1.3x"

    strings:
        $pattern = { 6A ?? FF 15 ?? ?? ?? ?? A3 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Free_Pascal_v09910
{
    meta:
        description = "Free Pascal v0.99.10"

    strings:
        $pattern = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 00 6E 00 00 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10 29 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Free_Pascal_v1010_win32_GUI
{
    meta:
        description = "Free Pascal v1.0.10 (win32 GUI)"

    strings:
        $pattern = { C6 05 ?? ?? ?? 00 00 E8 ?? ?? 00 00 50 E8 00 00 00 00 FF 25 ?? ?? ?? 00 55 89 E5 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Free_Pascal_v1010_win32_console
{
    meta:
        description = "Free Pascal v1.0.10 (win32 console)"

    strings:
        $pattern = { C6 05 ?? ?? ?? 00 01 E8 ?? ?? 00 00 C6 05 ?? ?? ?? 00 00 E8 ?? ?? 00 00 50 E8 00 00 00 00 FF 25 ?? ?? ?? 00 55 89 E5 ?? EC }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Free_Pascal_v106
{
    meta:
        description = "Free Pascal v1.06"

    strings:
        $pattern = { C6 05 ?? ?? 40 00 ?? E8 ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule LCC_Win32_v1x
{
    meta:
        description = "LCC Win32 v1.x"

    strings:
        $pattern = { 64 A1 ?? ?? ?? ?? 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 ?? 50 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule LCC_Win32_DLL
{
    meta:
        description = "LCC Win32 DLL"

    strings:
        $pattern = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 ?? ?? ?? FF 75 10 FF 75 0C FF 75 08 A1 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Metrowerks_CodeWarrior_v20_GUI
{
    meta:
        description = "Metrowerks CodeWarrior v2.0 (GUI)"

    strings:
        $pattern = { 55 89 E5 53 56 83 EC 44 55 B8 FF FF FF FF 50 50 68 ?? ?? 40 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? 00 00 E8 ?? ?? 00 00 E8 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Metrowerks_CodeWarrior_v20_Console
{
    meta:
        description = "Metrowerks CodeWarrior v2.0 (Console)"

    strings:
        $pattern = { 55 89 E5 55 B8 FF FF FF FF 50 50 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? 00 00 E8 ?? ?? 00 00 E8 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Metrowerks_CodeWarrior_DLL_v20
{
    meta:
        description = "Metrowerks CodeWarrior (DLL) v2.0"

    strings:
        $pattern = { 55 89 E5 53 56 57 8B 75 0C 8B 5D 10 83 FE 01 74 05 83 FE 02 75 12 53 56 FF 75 08 E8 6E FF FF FF 09 C0 75 04 31 C0 EB 21 53 56 FF 75 08 E8 ?? ?? ?? ?? 89 C7 09 F6 74 05 83 FE 03 75 0A 53 56 FF 75 08 E8 47 FF FF FF 89 F8 8D 65 F4 5F 5E 5B 5D C2 0C 00 C9 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Microsoft_Visual_Cpp
{
    meta:
        description = "Microsoft Visual C++"

    strings:
        $pattern = { 8B 44 24 08 56 83 E8 ?? 74 ?? 48 75 }
        $pattern_1 = { 8B 44 24 08 83 ?? ?? 74 }
        $pattern_2 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Microsoft_Visual_C_v20
{
    meta:
        description = "Microsoft Visual C v2.0"

    strings:
        $pattern = { 53 56 57 BB ?? ?? ?? ?? 8B ?? ?? ?? 55 3B FB 75 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Microsoft_Visual_Cpp_vxx
{
    meta:
        description = "Microsoft Visual C++ vx.x"

    strings:
        $pattern = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 }
        $pattern_1 = { 55 8B EC 56 57 BF ?? ?? ?? ?? 8B ?? ?? 3B F7 0F }
        $pattern_2 = { 53 55 56 8B ?? ?? ?? 85 F6 57 B8 ?? ?? ?? ?? 75 ?? 8B ?? ?? ?? ?? ?? 85 C9 75 ?? 33 C0 5F 5E 5D 5B C2 }
        $pattern_3 = { 55 8B EC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? 83 ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Microsoft_Visual_Cpp_v4x
{
    meta:
        description = "Microsoft Visual C++ v4.x"

    strings:
        $pattern = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 00 00 00 00 83 EC ?? 53 56 57 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Microsoft_Visual_Cpp_v42
{
    meta:
        description = "Microsoft Visual C++ v4.2"

    strings:
        $pattern = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 ?? ?? ?? ?? ?? ?? 83 ?? ?? 53 56 57 89 ?? ?? FF }
        $pattern_1 = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 ?? ?? ?? ?? ?? ?? 83 ?? ?? 53 56 57 89 ?? ?? C7 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Microsoft_Visual_Cpp_v42_DLL
{
    meta:
        description = "Microsoft Visual C++ v4.2 DLL"

    strings:
        $pattern = { 53 B8 ?? ?? ?? ?? 8B ?? ?? ?? 56 57 85 DB 55 75 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Microsoft_Visual_Cpp_v50
{
    meta:
        description = "Microsoft Visual C++ v5.0"

    strings:
        $pattern = { 55 8B EC 6A FF 68 68 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 53 56 57 }
        $pattern_1 = { 55 8B EC 6A FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 ?? 53 56 57 89 65 E8 FF 15 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 10 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Microsoft_Visual_Cpp_v50_DLL
{
    meta:
        description = "Microsoft Visual C++ v5.0 DLL"

    strings:
        $pattern = { ?? ?? 24 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 8B ?? 24 0C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Microsoft_Visual_Cpp_v50_v60_MFC
{
    meta:
        description = "Microsoft Visual C++ v5.0/v6.0 (MFC)"

    strings:
        $pattern = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Microsoft_Visual_Cpp_vxx_DLL
{
    meta:
        description = "Microsoft Visual C++ vx.x DLL"

    strings:
        $pattern = { ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? 00 ?? 00 ?? ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? 00 ?? 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Microsoft_Visual_Cpp_v60_SPx
{
    meta:
        description = "Microsoft Visual C++ v6.0 SPx"

    strings:
        $pattern = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 8B F0 8A ?? 3C 22 }
        $pattern_1 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 6A 01 8B F0 FF 15 }
        $pattern_2 = { 55 8B EC 6A FF 68 68 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 53 56 57 }
        $pattern_3 = { 55 8B EC 83 EC 50 53 56 57 BE ?? ?? ?? ?? 8D 7D F4 A5 A5 66 A5 8B }
        $pattern_4 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? 0D ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 1C ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 }
        $pattern_5 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 }
        $pattern_6 = { 55 8B EC 6A FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC ?? 53 56 57 89 65 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Microsoft_Visual_Cpp_v60_DLL
{
    meta:
        description = "Microsoft Visual C++ v6.0 DLL"

    strings:
        $pattern = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 51 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 8B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4D ?? ?? ?? ?? 02 }
        $pattern_1 = { 83 7C 24 08 01 75 09 8B 44 24 04 A3 ?? ?? 00 10 E8 8B FF FF FF }
        $pattern_2 = { 55 8D 6C ?? ?? 81 EC ?? ?? ?? ?? 8B 45 ?? 83 F8 01 56 0F 84 ?? ?? ?? ?? 85 C0 0F 84 }
        $pattern_3 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C }
        $pattern_4 = { 8B 44 ?? 08 }
        $pattern_5 = { 55 8B EC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Microsoft_Visual_Cpp_v60_Debug_Version
{
    meta:
        description = "Microsoft Visual C++ v6.0 (Debug Version)"

    strings:
        $pattern = { 55 8B EC 51 ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Microsoft_Visual_Cpp_v70_64_Bit
{
    meta:
        description = "Microsoft Visual C++ v7.0 (64 Bit)"

    strings:
        $pattern = { ?? ?? 41 00 00 00 00 00 00 00 63 00 00 00 00 00 ?? 00 ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 20 ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 }
        $pattern_1 = { 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 8B C7 E8 ?? ?? ?? ?? 89 65 ?? 8B F4 89 3E 56 FF 15 ?? ?? ?? ?? 8B 4E ?? 89 0D ?? ?? ?? ?? 8B 46 ?? A3 }
        $pattern_2 = { 6A ?? 68 ?? ?? ?? ?? E8 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Microsoft_Visual_Cpp_v70_DLL
{
    meta:
        description = "Microsoft Visual C++ v7.0 DLL"

    strings:
        $pattern = { 55 8D 6C ?? ?? 81 EC ?? ?? ?? ?? 8B 45 ?? 83 F8 01 56 0F 84 ?? ?? ?? ?? 85 C0 0F 84 }
        $pattern_1 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 ?? ?? 83 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Microsoft_Visual_CSharp_v70___Basic_NET
{
    meta:
        description = "Microsoft Visual C# v7.0 / Basic .NET"

    strings:
        $pattern = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $pattern_1 = { FF 25 00 20 00 11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Microsoft_Visual_Cpp_DLL
{
    meta:
        description = "Microsoft Visual C++ DLL"

    strings:
        $pattern = { 53 55 56 8B 74 24 14 85 F6 57 B8 01 00 00 00 }
        $pattern_1 = { 53 56 57 BB 01 ?? ?? ?? 8B ?? 24 14 }
        $pattern_2 = { 53 B8 01 00 00 00 8B 5C 24 0C 56 57 85 DB 55 75 12 83 3D ?? ?? ?? ?? ?? 75 09 33 C0 }
        $pattern_3 = { 55 8B EC 56 57 BF 01 00 00 00 8B 75 0C }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Microsoft_Visual_Basic_v50
{
    meta:
        description = "Microsoft Visual Basic v5.0"

    strings:
        $pattern = { ?? ?? ?? ?? ?? ?? ?? FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Microsoft_Visual_Basic_v50___v60
{
    meta:
        description = "Microsoft Visual Basic v5.0 - v6.0"

    strings:
        $pattern = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 00 00 ?? 00 00 00 30 ?? 00 ?? }
        $pattern_1 = { FF 25 ?? ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? FF FF FF }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Microsoft_Visual_Basic_v60
{
    meta:
        description = "Microsoft Visual Basic v6.0"

    strings:
        $pattern = { FF 25 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? FF FF FF ?? ?? ?? ?? ?? ?? 30 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Microsoft_Visual_Basic_v60_DLL
{
    meta:
        description = "Microsoft Visual Basic v6.0 DLL"

    strings:
        $pattern = { 5A 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 E9 ?? ?? FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule MinGW_GCC_v2x
{
    meta:
        description = "MinGW GCC v2.x"

    strings:
        $pattern = { 55 89 E5 E8 ?? ?? ?? ?? C9 C3 ?? ?? 45 58 45 }
        $pattern_1 = { 55 89 E5 ?? ?? ?? ?? ?? ?? FF FF ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }
        $pattern_2 = { 55 89 E5 E8 ?? ?? ?? ?? C9 C3 ?? ?? 45 58 45 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule MinGW_GCC_DLL_v2xx
{
    meta:
        description = "MinGW GCC DLL v2xx"

    strings:
        $pattern = { 55 89 E5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? 68 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule MinGW_v32x_Dll_main
{
    meta:
        description = "MinGW v3.2.x (Dll_main)"

    strings:
        $pattern = { 55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 96 01 00 00 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D 00 30 00 10 85 C9 75 10 31 DB 89 D8 8B 5D F8 8B 75 FC 89 EC 5D C2 0C 00 E8 59 00 00 00 EB EB 8D B4 26 00 00 00 00 85 C0 75 D0 E8 47 00 00 00 EB C9 90 8D 74 26 00 C7 04 24 80 00 00 00 E8 F4 05 00 00 A3 00 30 00 10 85 C0 74 1A C7 00 00 00 00 00 A3 10 30 00 10 E8 3B 02 00 00 E8 C6 01 00 00 E9 75 FF FF FF E8 BC 05 00 00 C7 00 0C 00 00 00 31 C0 EB 98 89 F6 55 89 E5 83 EC 08 89 5D FC 8B 15 00 30 00 10 85 D2 74 29 8B 1D 10 30 00 10 83 EB 04 39 D3 72 0D 8B 03 85 C0 75 2A 83 EB 04 39 D3 73 F3 89 14 24 E8 6B 05 00 00 31 C0 A3 00 30 00 10 C7 04 24 00 00 00 00 E8 48 05 00 00 8B 5D FC 89 EC 5D C3 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule MinGW_v32x_Dll_WinMain
{
    meta:
        description = "MinGW v3.2.x (Dll_WinMain)"

    strings:
        $pattern = { 55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 76 01 00 00 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D 00 30 00 10 85 C9 75 10 31 DB 89 D8 8B 5D F8 8B 75 FC 89 EC 5D C2 0C 00 E8 59 00 00 00 EB EB 8D B4 26 00 00 00 00 85 C0 75 D0 E8 47 00 00 00 EB C9 90 8D 74 26 00 C7 04 24 80 00 00 00 E8 A4 05 00 00 A3 00 30 00 10 85 C0 74 1A C7 00 00 00 00 00 A3 10 30 00 10 E8 1B 02 00 00 E8 A6 01 00 00 E9 75 FF FF FF E8 6C 05 00 00 C7 00 0C 00 00 00 31 C0 EB 98 89 F6 55 89 E5 83 EC 08 89 5D FC 8B 15 00 30 00 10 85 D2 74 29 8B 1D 10 30 00 10 83 EB 04 39 D3 72 0D 8B 03 85 C0 75 2A 83 EB 04 39 D3 73 F3 89 14 24 E8 1B 05 00 00 31 C0 A3 00 30 00 10 C7 04 24 00 00 00 00 E8 F8 04 00 00 8B 5D FC 89 EC 5D C3 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule MinGW_v32x_main
{
    meta:
        description = "MinGW v3.2.x (main)"

    strings:
        $pattern = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 E4 40 40 00 E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 E4 40 40 00 E8 48 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 00 41 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 F4 40 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 53 83 EC 24 C7 04 24 A0 11 40 00 E8 8D 07 00 00 83 EC 04 E8 85 02 00 00 C7 04 24 00 20 40 00 8B 15 10 20 40 00 8D 4D F8 C7 45 F8 00 00 00 00 89 4C 24 10 89 54 24 0C 8D 55 F4 89 54 24 08 C7 44 24 04 04 20 40 00 E8 02 07 00 00 A1 20 20 40 00 85 C0 74 76 A3 30 20 40 00 A1 F0 40 40 00 85 C0 74 1F 89 04 24 E8 C3 06 00 00 8B 1D 20 20 40 00 89 04 24 89 5C 24 04 E8 C1 06 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule MinGW_v32x_WinMain
{
    meta:
        description = "MinGW v3.2.x (WinMain)"

    strings:
        $pattern = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 FC 40 40 00 E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 FC 40 40 00 E8 48 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 18 41 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 0C 41 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 53 83 EC 24 C7 04 24 A0 11 40 00 E8 5D 08 00 00 83 EC 04 E8 55 03 00 00 C7 04 24 00 20 40 00 8B 15 10 20 40 00 8D 4D F8 C7 45 F8 00 00 00 00 89 4C 24 10 89 54 24 0C 8D 55 F4 89 54 24 08 C7 44 24 04 04 20 40 00 E8 D2 07 00 00 A1 20 20 40 00 85 C0 74 76 A3 30 20 40 00 A1 08 41 40 00 85 C0 74 1F 89 04 24 E8 93 07 00 00 8B 1D 20 20 40 00 89 04 24 89 5C 24 04 E8 91 07 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule MinGW_v32x_Dll_mainCRTStartup
{
    meta:
        description = "MinGW v3.2.x (Dll_mainCRTStartup)"

    strings:
        $pattern = { 55 89 E5 83 EC 08 6A 00 6A 00 6A 00 6A 00 E8 0D 00 00 00 B8 00 00 00 00 C9 C3 90 90 90 90 90 90 FF 25 38 20 00 10 90 90 00 00 00 00 00 00 00 00 FF FF FF FF 00 00 00 00 FF FF FF FF 00 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule MinGW_v32x__mainCRTStartup
{
    meta:
        description = "MinGW v3.2.x (_mainCRTStartup)"

    strings:
        $pattern = { 55 89 E5 83 EC 08 6A 00 6A 00 6A 00 6A 00 E8 0D 00 00 00 B8 00 00 00 00 C9 C3 90 90 90 90 90 90 FF 25 38 20 40 00 90 90 00 00 00 00 00 00 00 00 FF FF FF FF 00 00 00 00 FF FF FF FF 00 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule TASM___MASM
{
    meta:
        description = "TASM / MASM"

    strings:
        $pattern = { 6A 00 E8 ?? ?? 00 00 A3 ?? ?? 40 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Stranik_13_Modula_C_Pascal
{
    meta:
        description = "Stranik 1.3 Modula/C/Pascal"

    strings:
        $pattern = { E8 ?? ?? FF FF E8 ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 ?? ?? ?? 00 ?? ?? 00 ?? 00 ?? 00 00 ?? 00 ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? 00 ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 ?? ?? 00 ?? ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule WATCOM_C_Cpp_32_Run_Time_System_1988_1995
{
    meta:
        description = "WATCOM C/C++ 32 Run-Time System 1988-1995"

    strings:
        $pattern = { E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 }
        $pattern_1 = { E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule WATCOM_C_Cpp_32_Run_Time_System_1988_1994
{
    meta:
        description = "WATCOM C/C++ 32 Run-Time System 1988-1994"

    strings:
        $pattern = { FB 83 ?? ?? 89 E3 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 66 ?? ?? ?? 66 ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 29 C0 B4 30 CD 21 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule WATCOM_C_Cpp_DLL
{
    meta:
        description = "WATCOM C/C++ DLL"

    strings:
        $pattern = { 53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule BJFnt_v11b
{
    meta:
        description = ".BJFnt v1.1b"

    strings:
        $pattern = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule BJFnt_v12_RC
{
    meta:
        description = ".BJFnt v1.2 RC"

    strings:
        $pattern = { EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule BJFnt_v13
{
    meta:
        description = ".BJFnt v1.3"

    strings:
        $pattern = { EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20 60 }
        $pattern_1 = { EB ?? 3A ?? ?? 1E EB ?? CD 20 9C EB ?? CD 20 EB ?? CD 20 60 EB }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule _32Lite_v003a
{
    meta:
        description = "32Lite v0.03a"

    strings:
        $pattern = { 60 06 FC 1E 07 BE ?? ?? ?? ?? 6A 04 68 ?? 10 ?? ?? 68 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Alex_Protector_v04_beta_1_by_Alex
{
    meta:
        description = "Alex Protector v0.4 beta 1 by Alex"

    strings:
        $pattern = { 60 E8 01 00 00 00 C7 83 C4 04 33 C9 E8 01 00 00 00 68 83 C4 04 E8 01 00 00 00 68 83 C4 04 B9 ?? 00 00 00 E8 01 00 00 00 68 83 C4 04 E8 00 00 00 00 E8 01 00 00 00 C7 83 C4 04 8B 2C 24 83 C4 04 E8 01 00 00 00 A9 83 C4 04 81 ED 3C 13 40 00 E8 01 00 00 00 68 83 C4 04 E8 00 00 00 00 E8 00 00 00 00 49 E8 01 00 00 00 68 83 C4 04 85 C9 75 DF E8 B9 02 00 00 E8 01 00 00 00 C7 83 C4 04 8D 95 63 14 40 00 E8 01 00 00 00 C7 83 C4 04 90 90 90 E8 CA 01 00 00 01 02 03 04 05 68 90 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Alex_Protector_10_beta_2_by_Alex
{
    meta:
        description = "Alex Protector 1.0 beta 2 by Alex"

    strings:
        $pattern = { 60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 EB 01 E9 8B 44 24 0C EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 83 80 B8 00 00 00 02 33 C0 EB 01 E9 C3 58 83 C4 04 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 EB 01 E9 FF FF 60 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 0F 31 8B D8 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 8B CA EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 0F 31 2B C3 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 1B D1 0F 31 03 C3 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 13 D1 0F 31 2B C3 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 EB 05 68 F0 0F C7 C8 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 1B D1 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 85 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule AcidCrypt
{
    meta:
        description = "AcidCrypt"

    strings:
        $pattern = { 60 B9 ?? ?? ?? 00 BA ?? ?? ?? 00 BE ?? ?? ?? 00 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB }
        $pattern_1 = { BE ?? ?? ?? ?? 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Alloy_v1x2000
{
    meta:
        description = "Alloy v1.x.2000"

    strings:
        $pattern = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95 46 23 40 ?? 0B }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v160a
{
    meta:
        description = "Armadillo v1.60a"

    strings:
        $pattern = { 55 8B EC 6A FF 68 98 71 40 00 68 48 2D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v171
{
    meta:
        description = "Armadillo v1.71"

    strings:
        $pattern = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v172___v173
{
    meta:
        description = "Armadillo v1.72 - v1.73"

    strings:
        $pattern = { 55 8B EC 6A FF 68 E8 C1 ?? ?? 68 F4 86 ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v177
{
    meta:
        description = "Armadillo v1.77"

    strings:
        $pattern = { 55 8B EC 6A FF 68 B0 71 40 00 68 6C 37 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v180
{
    meta:
        description = "Armadillo v1.80"

    strings:
        $pattern = { 55 8B EC 6A FF 68 E8 C1 00 00 68 F4 86 00 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v182
{
    meta:
        description = "Armadillo v1.82"

    strings:
        $pattern = { 55 8B EC 6A FF 68 E0 C1 40 00 68 74 81 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v183
{
    meta:
        description = "Armadillo v1.83"

    strings:
        $pattern = { 55 8B EC 6A FF 68 E0 C1 40 00 68 64 84 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v184
{
    meta:
        description = "Armadillo v1.84"

    strings:
        $pattern = { 55 8B EC 6A FF 68 E8 C1 40 00 68 F4 86 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v190
{
    meta:
        description = "Armadillo v1.90"

    strings:
        $pattern = { 55 8B EC 6A FF 68 10 F2 40 00 68 64 9A 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v19x
{
    meta:
        description = "Armadillo v1.9x"

    strings:
        $pattern = { 55 8B EC 6A FF 68 98 ?? ?? ?? 68 10 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v190b1
{
    meta:
        description = "Armadillo v1.90b1"

    strings:
        $pattern = { 55 8B EC 6A FF 68 E0 C1 40 00 68 04 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v190b2
{
    meta:
        description = "Armadillo v1.90b2"

    strings:
        $pattern = { 55 8B EC 6A FF 68 F0 C1 40 00 68 A4 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v190b3
{
    meta:
        description = "Armadillo v1.90b3"

    strings:
        $pattern = { 55 8B EC 6A FF 68 08 E2 40 00 68 94 95 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v190b4
{
    meta:
        description = "Armadillo v1.90b4"

    strings:
        $pattern = { 55 8B EC 6A FF 68 08 E2 40 00 68 B4 96 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v190a
{
    meta:
        description = "Armadillo v1.90a"

    strings:
        $pattern = { 55 8B EC 64 FF 68 10 F2 40 00 68 14 9B 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v190c
{
    meta:
        description = "Armadillo v1.90c"

    strings:
        $pattern = { 55 8B EC 6A FF 68 10 F2 40 00 68 74 9D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v200
{
    meta:
        description = "Armadillo v2.00"

    strings:
        $pattern = { 55 8B EC 6A FF 68 00 02 41 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v200b1
{
    meta:
        description = "Armadillo v2.00b1"

    strings:
        $pattern = { 55 8B EC 6A FF 68 98 ?? ?? ?? 68 10 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v200b2_200b3
{
    meta:
        description = "Armadillo v2.00b2-2.00b3"

    strings:
        $pattern = { 55 8B EC 6A FF 68 00 F2 40 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v201
{
    meta:
        description = "Armadillo v2.01"

    strings:
        $pattern = { 55 8B EC 6A FF 68 08 02 41 00 68 04 9A 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v210b2
{
    meta:
        description = "Armadillo v2.10b2"

    strings:
        $pattern = { 55 8B EC 6A FF 68 18 12 41 00 68 24 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v220
{
    meta:
        description = "Armadillo v2.20"

    strings:
        $pattern = { 55 8B EC 6A FF 68 10 12 41 00 68 F4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v220b1
{
    meta:
        description = "Armadillo v2.20b1"

    strings:
        $pattern = { 55 8B EC 6A FF 68 30 12 41 00 68 A4 A5 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v250
{
    meta:
        description = "Armadillo v2.50"

    strings:
        $pattern = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 F8 ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 20 ?? ?? ?? 33 D2 8A D4 89 15 D0 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v250b1
{
    meta:
        description = "Armadillo v2.50b1"

    strings:
        $pattern = { 55 8B EC 6A FF 68 98 ?? ?? ?? 68 10 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v250b3
{
    meta:
        description = "Armadillo v2.50b3"

    strings:
        $pattern = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 F8 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 20 ?? ?? ?? 33 D2 8A D4 89 15 D0 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v251
{
    meta:
        description = "Armadillo v2.51"

    strings:
        $pattern = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 D0 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 20 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v252_beta2
{
    meta:
        description = "Armadillo v2.52 beta2"

    strings:
        $pattern = { 55 8B EC 6A FF 68 ?? ?? ?? ?? B0 ?? ?? ?? ?? 68 60 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 24 }
        $pattern_1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? E0 ?? ?? ?? ?? 68 D4 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 38 }
        $pattern_2 = { 55 8B EC 6A FF 68 E0 ?? ?? ?? 68 D4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 38 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Armadillo_v252b2
{
    meta:
        description = "Armadillo v2.52b2"

    strings:
        $pattern = { 55 8B EC 6A FF 68 B0 ?? ?? ?? 68 60 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 24 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v253
{
    meta:
        description = "Armadillo v2.53"

    strings:
        $pattern = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 40 ?? ?? ?? ?? 68 54 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 58 33 D2 8A D4 89 }
        $pattern_1 = { 55 8B EC 6A FF 68 40 ?? ?? ?? 68 54 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 EC }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Armadillo_v253b3
{
    meta:
        description = "Armadillo v2.53b3"

    strings:
        $pattern = { 55 8B EC 6A FF 68 D8 ?? ?? ?? 68 14 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v2xx_CopyMem_II
{
    meta:
        description = "Armadillo v2.xx (CopyMem II)"

    strings:
        $pattern = { 6A ?? 8B B5 ?? ?? ?? ?? C1 E6 04 8B 85 ?? ?? ?? ?? 25 07 ?? ?? 80 79 05 48 83 C8 F8 40 33 C9 8A 88 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 81 E2 07 ?? ?? 80 79 05 4A 83 CA F8 42 33 C0 8A 82 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v25x___v26x
{
    meta:
        description = "Armadillo v2.5x - v2.6x"

    strings:
        $pattern = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 EC }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v260
{
    meta:
        description = "Armadillo v2.60"

    strings:
        $pattern = { 55 8B EC 6A FF 68 D0 ?? ?? ?? 68 34 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 68 ?? ?? ?? 33 D2 8A D4 89 15 84 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v260b1
{
    meta:
        description = "Armadillo v2.60b1"

    strings:
        $pattern = { 55 8B EC 6A FF 68 50 ?? ?? ?? 68 74 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 FC }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v260b2
{
    meta:
        description = "Armadillo v2.60b2"

    strings:
        $pattern = { 55 8B EC 6A FF 68 90 ?? ?? ?? 68 24 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 60 ?? ?? ?? 33 D2 8A D4 89 15 3C }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v260a
{
    meta:
        description = "Armadillo v2.60a"

    strings:
        $pattern = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 94 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 B4 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v260c
{
    meta:
        description = "Armadillo v2.60c"

    strings:
        $pattern = { 55 8B EC 6A FF 68 40 ?? ?? ?? 68 F4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 F4 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v261
{
    meta:
        description = "Armadillo v2.61"

    strings:
        $pattern = { 55 8B EC 6A FF 68 28 ?? ?? ?? 68 E4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 0C }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v265b1
{
    meta:
        description = "Armadillo v2.65b1"

    strings:
        $pattern = { 55 8B EC 6A FF 68 38 ?? ?? ?? 68 40 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 F4 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v275a
{
    meta:
        description = "Armadillo v2.75a"

    strings:
        $pattern = { 55 8B EC 6A FF 68 68 ?? ?? ?? 68 D0 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 24 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v285
{
    meta:
        description = "Armadillo v2.85"

    strings:
        $pattern = { 55 8B EC 6A FF 68 68 ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 24 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v300
{
    meta:
        description = "Armadillo v3.00"

    strings:
        $pattern = { 60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 60 33 C9 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v300a
{
    meta:
        description = "Armadillo v3.00a"

    strings:
        $pattern = { 60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v301_v305
{
    meta:
        description = "Armadillo v3.01, v3.05"

    strings:
        $pattern = { 60 E8 00 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 60 33 C9 75 02 EB 15 EB 33 C9 75 18 7A 0C 70 0E EB 0D E8 72 0E 79 F1 FF 15 00 79 09 74 F0 EB 87 DB 7A F0 A0 33 61 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 60 9C 33 C0 E8 09 00 00 00 E8 E8 23 00 00 00 7A 23 A0 8B 04 24 EB 03 7A 29 E9 C6 00 90 C3 E8 70 F0 87 D2 71 07 E9 00 40 8B DB 7A 11 EB 08 E9 EB F7 EB C3 E8 7A E9 70 DA 7B D1 71 F3 E9 7B }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v310
{
    meta:
        description = "Armadillo v3.10"

    strings:
        $pattern = { 55 8B EC 6A FF 68 E0 97 44 00 68 20 C0 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 4C 41 44 00 33 D2 8A D4 89 15 90 A1 44 00 8B C8 81 E1 FF 00 00 00 89 0D 8C A1 44 00 C1 E1 08 03 CA 89 0D 88 A1 44 00 C1 E8 10 A3 84 A1 44 00 33 F6 56 E8 72 16 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 3D 13 00 00 FF 15 30 40 44 00 A3 84 B7 44 00 E8 FB 11 00 00 A3 E0 A1 44 00 E8 A4 0F 00 00 E8 E6 0E 00 00 E8 4E F6 FF FF 89 75 D0 8D 45 A4 50 FF 15 38 40 44 00 E8 77 0E 00 00 89 45 9C F6 45 D0 01 74 06 0F B7 45 D4 EB 03 6A 0A 58 50 FF 75 9C 56 56 FF 15 7C 41 44 00 50 E8 49 D4 FE FF 89 45 A0 50 E8 3C F6 FF FF 8B 45 EC 8B 08 8B 09 89 4D 98 50 51 E8 B5 0C 00 00 59 59 C3 8B 65 E8 FF 75 98 E8 2E F6 FF FF 83 3D E8 A1 44 00 01 75 05 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v3xx
{
    meta:
        description = "Armadillo v3.xx"

    strings:
        $pattern = { 60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Armadillo_v4x
{
    meta:
        description = "Armadillo v4.x"

    strings:
        $pattern = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ARM_Protector_v01_by_SMoKE
{
    meta:
        description = "ARM Protector v0.1 by SMoKE"

    strings:
        $pattern = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 01 00 8D 8D 92 31 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule APatch_GUI_v11
{
    meta:
        description = "APatch GUI v1.1"

    strings:
        $pattern = { 52 31 C0 E8 FF FF FF FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPack_v100b
{
    meta:
        description = "ASPack v1.00b"

    strings:
        $pattern = { 60 E8 ?? ?? ?? ?? 5D 81 ED 92 1A 44 ?? B8 8C 1A 44 ?? 03 C5 2B 85 CD 1D 44 ?? 89 85 D9 1D 44 ?? 80 BD C4 1D 44 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPack_v101b
{
    meta:
        description = "ASPack v1.01b"

    strings:
        $pattern = { 60 E8 ?? ?? ?? ?? 5D 81 ED D2 2A 44 ?? B8 CC 2A 44 ?? 03 C5 2B 85 A5 2E 44 ?? 89 85 B1 2E 44 ?? 80 BD 9C 2E 44 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPack_v102a
{
    meta:
        description = "ASPack v1.02a"

    strings:
        $pattern = { 60 E8 ?? ?? ?? ?? 5D 81 ED 3E D9 43 ?? B8 38 ?? ?? ?? 03 C5 2B 85 0B DE 43 ?? 89 85 17 DE 43 ?? 80 BD 01 DE 43 ?? ?? 75 15 FE 85 01 DE 43 ?? E8 1D ?? ?? ?? E8 79 02 ?? ?? E8 12 03 ?? ?? 8B 85 03 DE 43 ?? 03 85 17 DE 43 ?? 89 44 24 1C 61 FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPack_v102b
{
    meta:
        description = "ASPack v1.02b"

    strings:
        $pattern = { 60 E8 ?? ?? ?? ?? 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03 C5 2B 85 7D 7C 43 ?? 89 85 89 7C 43 ?? 80 BD 74 7C 43 }
        $pattern_1 = { 60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule ASPack_v103b
{
    meta:
        description = "ASPack v1.03b"

    strings:
        $pattern = { 60 E8 ?? ?? ?? ?? 5D 81 ED AE 98 43 ?? B8 A8 98 43 ?? 03 C5 2B 85 18 9D 43 ?? 89 85 24 9D 43 ?? 80 BD 0E 9D 43 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPack_v104b
{
    meta:
        description = "ASPack v1.04b"

    strings:
        $pattern = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 12 9D ?? 89 85 1E 9D ?? ?? 80 BD 08 9D }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPack_v105b
{
    meta:
        description = "ASPack v1.05b"

    strings:
        $pattern = { 60 E8 ?? ?? ?? ?? 5D 81 ED CE 3A 44 ?? B8 C8 3A 44 ?? 03 C5 2B 85 B5 3E 44 ?? 89 85 C1 3E 44 ?? 80 BD AC 3E 44 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPack_v106b
{
    meta:
        description = "ASPack v1.06b"

    strings:
        $pattern = { 90 75 00 E9 }
        $pattern_1 = { 90 90 75 00 E9 }
        $pattern_2 = { 90 90 90 75 00 E9 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule ASPack_v1061b
{
    meta:
        description = "ASPack v1.061b"

    strings:
        $pattern = { 60 E8 ?? ?? ?? ?? 5D 81 ED EA A8 43 ?? B8 E4 A8 43 ?? 03 C5 2B 85 78 AD 43 ?? 89 85 84 AD 43 ?? 80 BD 6E AD 43 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPack_v107b
{
    meta:
        description = "ASPack v1.07b"

    strings:
        $pattern = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 0B DE ?? 89 85 17 DE ?? ?? 80 BD 01 DE }
        $pattern_1 = { 90 90 90 75 ?? E9 }
        $pattern_2 = { 90 90 75 ?? E9 }
        $pattern_3 = { 90 75 ?? E9 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule ASPack_v107b_DLL
{
    meta:
        description = "ASPack v1.07b (DLL)"

    strings:
        $pattern = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPack_v108
{
    meta:
        description = "ASPack v1.08"

    strings:
        $pattern = { 90 75 01 FF E9 }
        $pattern_1 = { 90 90 75 01 FF E9 }
        $pattern_2 = { 90 90 90 75 01 FF E9 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule ASPack_v10801
{
    meta:
        description = "ASPack v1.08.01"

    strings:
        $pattern = { 90 90 90 75 ?? 90 E9 }
        $pattern_1 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 ?? BB 10 ?? 44 ?? 03 DD 2B 9D }
        $pattern_2 = { 90 90 75 ?? 90 E9 }
        $pattern_3 = { 90 75 ?? 90 E9 }
        $pattern_4 = { 60 EB ?? 5D EB ?? FF ?? ?? ?? ?? ?? E9 }
        $pattern_5 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 00 BB 10 ?? 44 00 03 DD 2B 9D }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule ASPack_v10802
{
    meta:
        description = "ASPack v1.08.02"

    strings:
        $pattern = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED 23 6A 44 00 BB 10 ?? 44 00 03 DD 2B 9D 72 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPack_v108x
{
    meta:
        description = "ASPack v1.08.x"

    strings:
        $pattern = { 60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED 1B 6A 44 00 BB 10 6A 44 00 03 DD 2B 9D 2A }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPack_v10803
{
    meta:
        description = "ASPack v1.08.03"

    strings:
        $pattern = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD }
        $pattern_1 = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD }
        $pattern_2 = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule ASPack_v10804
{
    meta:
        description = "ASPack v1.08.04"

    strings:
        $pattern = { 60 E8 41 06 00 00 EB 41 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPack_v2xx
{
    meta:
        description = "ASPack v2.xx"

    strings:
        $pattern = { A8 03 ?? ?? 61 75 08 B8 01 ?? ?? ?? C2 0C ?? 68 ?? ?? ?? ?? C3 8B 85 26 04 ?? ?? 8D 8D 3B 04 ?? ?? 51 50 FF 95 }
        $pattern_1 = { A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule ASPack_v2000
{
    meta:
        description = "ASPack v2.000"

    strings:
        $pattern = { 60 E8 70 05 00 00 EB 4C }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPack_v2001
{
    meta:
        description = "ASPack v2.001"

    strings:
        $pattern = { 60 E8 72 05 00 00 EB 4C }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPack_v21
{
    meta:
        description = "ASPack v2.1"

    strings:
        $pattern = { 60 E8 72 05 00 00 EB 33 87 DB 90 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPack_v211
{
    meta:
        description = "ASPack v2.11"

    strings:
        $pattern = { 60 E9 3D 04 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPack_v211b
{
    meta:
        description = "ASPack v2.11b"

    strings:
        $pattern = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 3D 04 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPack_v211c
{
    meta:
        description = "ASPack v2.11c"

    strings:
        $pattern = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 59 04 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPack_v211d
{
    meta:
        description = "ASPack v2.11d"

    strings:
        $pattern = { 60 E8 02 00 00 00 EB 09 5D 55 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPack_v212
{
    meta:
        description = "ASPack v2.12"

    strings:
        $pattern = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB }
        $pattern_1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Anticrack_Software_Protector_v109_ACProtect
{
    meta:
        description = "Anticrack Software Protector v1.09 (ACProtect)"

    strings:
        $pattern = { 60 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }
        $pattern_1 = { 60 ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 04 ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 78 03 79 01 ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 }
        $pattern_2 = { 60 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 83 04 24 06 C3 ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 }
        $pattern_3 = { 60 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule ASProtect_vxx
{
    meta:
        description = "ASProtect vx.x"

    strings:
        $pattern = { 90 60 ?? ?? ?? 00 00 }
        $pattern_1 = { 60 ?? ?? ?? ?? ?? 90 5D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 DD }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule ASProtect_v10
{
    meta:
        description = "ASProtect v1.0"

    strings:
        $pattern = { 60 E8 01 ?? ?? ?? 90 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASProtect_v11
{
    meta:
        description = "ASProtect v1.1"

    strings:
        $pattern = { 60 E9 ?? 04 ?? ?? E9 ?? ?? ?? ?? ?? ?? ?? EE }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASProtect_v11_MTE
{
    meta:
        description = "ASProtect v1.1 MTE"

    strings:
        $pattern = { 60 E9 ?? ?? ?? ?? 91 78 79 79 79 E9 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASProtect_v11_MTEb
{
    meta:
        description = "ASProtect v1.1 MTEb"

    strings:
        $pattern = { 90 60 E9 ?? 04 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASProtect_v11_MTEc
{
    meta:
        description = "ASProtect v1.1 MTEc"

    strings:
        $pattern = { 90 60 E8 1B ?? ?? ?? E9 FC }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASProtect_v11_BRS
{
    meta:
        description = "ASProtect v1.1 BRS"

    strings:
        $pattern = { 60 E9 ?? 05 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASProtect_v12
{
    meta:
        description = "ASProtect v1.2"

    strings:
        $pattern = { 68 01 ?? ?? ?? C3 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASProtect_v12x
{
    meta:
        description = "ASProtect v1.2x"

    strings:
        $pattern = { 00 00 68 01 ?? ?? ?? C3 AA }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASProtect_v12x_New_Strain
{
    meta:
        description = "ASProtect v1.2x (New Strain)"

    strings:
        $pattern = { 68 01 ?? ?? ?? E8 01 ?? ?? ?? C3 C3 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASProtect_v123_RC1
{
    meta:
        description = "ASProtect v1.23 RC1"

    strings:
        $pattern = { 68 01 ?? ?? 00 E8 01 00 00 00 C3 C3 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ACProtect_v132
{
    meta:
        description = "ACProtect v1.32"

    strings:
        $pattern = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E9 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASProtect_v20
{
    meta:
        description = "ASProtect v2.0"

    strings:
        $pattern = { 68 01 ?? 40 00 E8 01 00 00 00 C3 C3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2C }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ASPR_Stripper_v2x_unpacked
{
    meta:
        description = "ASPR Stripper v2.x unpacked"

    strings:
        $pattern = { BB ?? ?? ?? ?? E9 ?? ?? ?? ?? 60 9C FC BF ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 AA 9D 61 C3 55 8B EC }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule BamBam_v001
{
    meta:
        description = "BamBam v0.01"

    strings:
        $pattern = { 6A 14 E8 9A 05 00 00 8B D8 53 68 FB ?? ?? 00 E8 6C FD FF FF B9 05 00 00 00 8B F3 BF FB ?? ?? 00 53 F3 A5 E8 8D 05 00 00 8B 3D 03 ?? ?? 00 A1 2B ?? ?? 00 66 8B 15 2F ?? ?? 00 B9 80 ?? ?? 00 2B CF 89 45 E8 89 0D 6B ?? ?? 00 66 89 55 EC 8B 41 3C 33 D2 03 C1 83 C4 10 66 8B 48 06 66 8B 50 14 81 E1 FF FF 00 00 8D 5C 02 18 8D 41 FF 85 C0 0F 8E 39 01 00 00 89 45 F0 C6 45 FF 00 8D 7D E8 8B F3 8A 0E 8A 17 8A C1 3A CA 75 1E 84 C0 74 16 8A 56 01 8A 4F 01 8A C2 3A D1 75 0E 83 C6 02 83 C7 02 84 C0 75 DC 33 C0 EB 05 1B C0 83 D8 FF 85 C0 75 04 C6 45 FF 01 8B 43 10 85 C0 0F 84 DD 00 00 00 8B 43 08 50 E8 D7 04 00 00 8A 4D FF 83 C4 04 84 C9 8B 4B 08 89 45 F8 C7 45 F4 00 00 00 00 74 61 8B 15 07 ?? ?? 00 8B 35 6B ?? ?? 00 8B 7B 0C 2B CA 03 F2 8B D1 03 F7 8B F8 C1 E9 02 F3 A5 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Blade_Joiner_v15
{
    meta:
        description = "Blade Joiner v1.5"

    strings:
        $pattern = { 55 8B EC 81 C4 E4 FE FF FF 53 56 57 33 C0 89 45 F0 89 85 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule BopCrypt_v10
{
    meta:
        description = "BopCrypt v1.0"

    strings:
        $pattern = { 60 BD ?? ?? ?? ?? E8 ?? ?? 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule CExe_v10a
{
    meta:
        description = "CExe v1.0a"

    strings:
        $pattern = { 55 8B EC 81 EC 0C 02 ?? ?? 56 BE 04 01 ?? ?? 8D 85 F8 FE FF FF 56 50 6A ?? FF 15 54 10 40 ?? 8A 8D F8 FE FF FF 33 D2 84 C9 8D 85 F8 FE FF FF 74 16 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule CD_Cops_II
{
    meta:
        description = "CD-Cops II"

    strings:
        $pattern = { 53 60 BD ?? ?? ?? ?? 8D 45 ?? 8D 5D ?? E8 ?? ?? ?? ?? 8D }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule CodeCrypt_v014b
{
    meta:
        description = "CodeCrypt v0.14b"

    strings:
        $pattern = { E9 C5 02 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule CodeCrypt_v015b
{
    meta:
        description = "CodeCrypt v0.15b"

    strings:
        $pattern = { E9 31 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule CodeCrypt_v016b___v0163b
{
    meta:
        description = "CodeCrypt v0.16b - v0.163b"

    strings:
        $pattern = { E9 2E 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule CodeCrypt_v0164
{
    meta:
        description = "CodeCrypt v0.164"

    strings:
        $pattern = { E9 2E 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F EB 03 FF 1D 34 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Code_Lock_vxx
{
    meta:
        description = "Code-Lock vx.x"

    strings:
        $pattern = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule CodeSafe_v20
{
    meta:
        description = "CodeSafe v2.0"

    strings:
        $pattern = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 EC 10 53 56 57 E8 C4 01 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule CopyControl_v303
{
    meta:
        description = "CopyControl v3.03"

    strings:
        $pattern = { CC 90 90 EB 0B 01 50 51 52 53 54 61 33 61 2D 35 CA D1 07 52 D1 A1 3C }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule CreateInstall_Stub_vxx
{
    meta:
        description = "CreateInstall Stub vx.x"

    strings:
        $pattern = { 55 8B EC 81 EC 20 02 00 00 53 56 57 6A 00 FF 15 18 61 40 00 68 00 70 40 00 89 45 08 FF 15 14 61 40 00 85 C0 74 27 6A 00 A1 00 20 40 00 50 FF 15 3C 61 40 00 8B F0 6A 06 56 FF 15 38 61 40 00 6A 03 56 FF 15 38 61 40 00 E9 36 03 00 00 68 02 7F 00 00 33 F6 56 BF 00 30 00 00 FF 15 20 61 40 00 50 FF 15 2C 61 40 00 6A 04 57 68 00 FF 01 00 56 FF 15 CC 60 40 00 6A 04 A3 CC 35 40 00 57 68 00 0F 01 00 56 FF 15 CC 60 40 00 68 00 01 00 00 BE B0 3F 40 00 56 A3 C4 30 40 00 FF 75 08 FF 15 10 61 40 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule CreateInstall_v200335
{
    meta:
        description = "CreateInstall v2003.3.5"

    strings:
        $pattern = { 81 EC 0C 04 00 00 53 56 57 55 68 60 50 40 00 6A 01 6A 00 FF 15 D8 80 40 00 8B F0 FF 15 D4 80 40 00 3D B7 00 00 00 75 0F 56 FF 15 B8 80 40 00 6A 02 FF 15 A4 80 40 00 33 DB E8 F2 FE FF FF 68 02 7F 00 00 89 1D 94 74 40 00 53 89 1D 98 74 40 00 FF 15 E4 80 40 00 50 FF 15 E0 80 40 00 8B 0D 00 50 40 00 E8 68 FF FF FF B9 40 0D 03 00 89 44 24 14 E8 5A FF FF FF 68 00 02 00 00 8B 2D D0 80 40 00 89 44 24 1C 8D 44 24 20 50 53 FF D5 8D 4C 24 1C 53 68 00 00 00 80 8B 3D CC 80 40 00 6A 03 53 6A 03 68 00 00 00 80 51 FF D7 8B F0 53 8D 44 24 14 8B 0D 00 50 40 00 8B 54 24 18 50 51 52 56 FF 15 C8 80 40 00 85 C0 0F 84 40 02 00 00 8B 15 00 50 40 00 3B 54 24 10 0F 85 30 02 00 00 6A FF A1 04 50 40 00 2B D0 8B 4C 24 18 03 C8 E8 9F FE FF FF 3B 05 10 50 40 00 0F 85 10 02 00 00 56 FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Crunch_PE
{
    meta:
        description = "Crunch/PE"

    strings:
        $pattern = { 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Crunch_PE_v10xx
{
    meta:
        description = "Crunch/PE v1.0.x.x"

    strings:
        $pattern = { 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 80 BD ?? ?? ?? ?? ?? 75 09 C6 85 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Crunch_PE_v20xx
{
    meta:
        description = "Crunch/PE v2.0.x.x"

    strings:
        $pattern = { 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 55 BB ?? ?? ?? ?? 03 DD 53 64 67 FF 36 ?? ?? 64 67 89 26 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Crunch_PE_v30xx
{
    meta:
        description = "Crunch/PE v3.0.x.x"

    strings:
        $pattern = { EB 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 5D 81 ED 18 ?? ?? ?? 8B C5 55 60 9C 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? FF 74 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Crunch_v40
{
    meta:
        description = "Crunch v4.0"

    strings:
        $pattern = { EB 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 18 00 00 00 8B C5 55 60 9C 2B 85 E9 06 00 00 89 85 E1 06 00 00 FF 74 24 2C E8 BB 01 00 00 0F 82 92 05 00 00 E8 F1 03 00 00 49 0F 88 86 05 00 00 68 6C D9 B2 96 33 C0 50 E8 24 03 00 00 89 85 D9 41 00 00 68 EC 49 7B 79 33 C0 50 E8 11 03 00 00 89 85 D1 41 00 00 E8 67 05 00 00 E9 56 05 00 00 51 52 53 33 C9 49 8B D1 33 C0 33 DB AC 32 C1 8A CD 8A EA 8A D6 B6 08 66 D1 EB 66 D1 D8 73 09 66 35 20 83 66 81 F3 B8 ED FE CE 75 EB 33 C8 33 D3 4F 75 D5 F7 D2 F7 D1 5B 8B C2 C1 C0 10 66 8B C1 5A 59 C3 68 03 02 00 00 E8 80 04 00 00 0F 82 A8 02 00 00 96 8B 44 24 04 0F C8 8B D0 25 0F 0F 0F 0F 33 D0 C1 C0 08 0B C2 8B D0 25 33 33 33 33 33 D0 C1 C0 04 0B C2 8B D0 25 55 55 55 55 33 D0 C1 C0 02 0B C2 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule CrypKey_v5___v6
{
    meta:
        description = "CrypKey v5 - v6"

    strings:
        $pattern = { E8 ?? ?? ?? ?? 58 83 E8 05 50 5F 57 8B F7 81 EF ?? ?? ?? ?? 83 C6 39 BA ?? ?? ?? ?? 8B DF B9 0B ?? ?? ?? 8B 06 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule CrypWrap_vxx
{
    meta:
        description = "CrypWrap vx.x"

    strings:
        $pattern = { E8 B8 ?? ?? ?? E8 90 02 ?? ?? 83 F8 ?? 75 07 6A ?? E8 ?? ?? ?? ?? FF 15 49 8F 40 ?? A9 ?? ?? ?? 80 74 0E }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule CICompress_v10
{
    meta:
        description = "CICompress v1.0"

    strings:
        $pattern = { 6A 04 68 00 10 00 00 FF 35 9C 14 40 00 6A 00 FF 15 38 10 40 00 A3 FC 10 40 00 97 BE 00 20 40 00 E8 71 00 00 00 3B 05 9C 14 40 00 75 61 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00 C0 68 94 10 40 00 FF 15 2C 10 40 00 A3 F8 10 40 00 6A 00 68 F4 10 40 00 FF 35 9C 14 40 00 FF 35 FC 10 40 00 FF 35 F8 10 40 00 FF 15 34 10 40 00 FF 35 F8 10 40 00 FF 15 30 10 40 00 68 00 40 00 00 FF 35 9C 14 40 00 FF 35 FC 10 40 00 FF 15 3C 10 40 00 6A 00 FF 15 28 10 40 00 60 33 DB 33 C9 E8 7F 00 00 00 73 0A B1 08 E8 82 00 00 00 AA EB EF E8 6E 00 00 00 73 14 B1 04 E8 71 00 00 00 3C 00 74 EB 56 8B F7 2B F0 A4 5E EB D4 33 ED E8 51 00 00 00 72 10 B1 02 E8 54 00 00 00 3C 00 74 3B 8B E8 C1 C5 08 B1 08 E8 44 00 00 00 0B C5 50 33 ED E8 2E 00 00 00 72 0C B1 02 E8 31 00 00 00 8B E8 C1 C5 08 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule CipherWall_Self_Extrator_Decryptor_GUI_v15
{
    meta:
        description = "CipherWall Self-Extrator/Decryptor (GUI) v1.5"

    strings:
        $pattern = { 90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 F9 89 C7 6A 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD 00 F3 FF FF 83 D1 01 8D 14 2F 83 FD FC 76 0F 8A 02 42 88 07 47 49 75 F7 E9 63 FF FF FF 90 8B 02 83 C2 04 89 07 83 C7 04 83 E9 04 77 F1 01 CF E9 4C FF FF FF 5E 89 F7 B9 52 10 00 00 8A 07 47 2C E8 3C 01 77 F7 80 3F 0E 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule CipherWall_Self_Extrator_Decryptor_Console_v15
{
    meta:
        description = "CipherWall Self-Extrator/Decryptor (Console) v1.5"

    strings:
        $pattern = { 90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 0B 6E 5B 9B 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD 00 F3 FF FF 83 D1 01 8D 14 2F 83 FD FC 76 0F 8A 02 42 88 07 47 49 75 F7 E9 63 FF FF FF 90 8B 02 83 C2 04 89 07 83 C7 04 83 E9 04 77 F1 01 CF E9 4C FF FF FF 5E 89 F7 B9 12 10 00 00 8A 07 47 2C E8 3C 01 77 F7 80 3F 06 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule DAEMON_Protect_v067
{
    meta:
        description = "DAEMON Protect v0.6.7"

    strings:
        $pattern = { 60 60 9C 8C C9 32 C9 E3 0C 52 0F 01 4C 24 FE 5A 83 C2 0C 8B 1A 9D 61 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule DEF_v10
{
    meta:
        description = "DEF v1.0"

    strings:
        $pattern = { BE ?? 01 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? 10 40 00 C3 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Ding_Boys_PE_lock_v007
{
    meta:
        description = "Ding Boy's PE-lock v0.07"

    strings:
        $pattern = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 23 35 40 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Ding_Boys_PE_lock_Phantasm_v08
{
    meta:
        description = "Ding Boy's PE-lock Phantasm v0.8"

    strings:
        $pattern = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 0D 39 40 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Ding_Boys_PE_lock_Phantasm_v10___v11
{
    meta:
        description = "Ding Boy's PE-lock Phantasm v1.0 / v1.1"

    strings:
        $pattern = { 55 57 56 52 51 53 66 81 C3 EB 02 EB FC 66 81 C3 EB 02 EB FC }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Ding_Boys_PE_lock_Phantasm_v15b3
{
    meta:
        description = "Ding Boy's PE-lock Phantasm v1.5b3"

    strings:
        $pattern = { 9C 55 57 56 52 51 53 9C FA E8 00 00 00 00 5D 81 ED 5B 53 40 00 B0 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule DBPE_v153
{
    meta:
        description = "DBPE v1.53"

    strings:
        $pattern = { 9C 55 57 56 52 51 53 9C FA E8 ?? ?? ?? ?? 5D 81 ED 5B 53 40 ?? B0 ?? E8 ?? ?? ?? ?? 5E 83 C6 11 B9 27 ?? ?? ?? 30 06 46 49 75 FA }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule DBPE_v210
{
    meta:
        description = "DBPE v2.10"

    strings:
        $pattern = { 9C 6A 10 73 0B EB 02 C1 51 E8 06 ?? ?? ?? C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 01 E8 79 E0 7A 01 75 83 C4 04 9D EB 01 75 68 5F 20 40 ?? E8 B0 EF FF FF 72 03 73 01 75 BE }
        $pattern_1 = { EB 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? EB 58 75 73 65 72 33 32 2E 64 6C 6C ?? 4D 65 73 73 61 67 65 42 6F 78 41 ?? 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C ?? 53 6C 65 65 70 ?? 47 65 74 54 69 63 6B 43 6F 75 6E 74 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule DBPE_v233
{
    meta:
        description = "DBPE v2.33"

    strings:
        $pattern = { EB 20 ?? ?? 40 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 9C 6A 10 73 0B EB 02 C1 51 E8 06 ?? ?? ?? C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 01 E8 79 E0 7A 01 75 83 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule DBPE_vxxx
{
    meta:
        description = "DBPE vx.xx"

    strings:
        $pattern = { EB 20 ?? ?? 40 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule DxPack_10
{
    meta:
        description = "DxPack 1.0"

    strings:
        $pattern = { 60 E8 ?? ?? ?? ?? 5D 8B FD 81 ED ?? ?? ?? ?? 2B B9 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule DzA_Patcher_v13_Loader
{
    meta:
        description = "DzA Patcher v1.3 Loader"

    strings:
        $pattern = { BF 00 40 40 00 99 68 48 20 40 00 68 00 20 40 00 52 52 52 52 52 52 52 57 E8 15 01 00 00 85 C0 75 1C 99 52 52 57 52 E8 CB 00 00 00 FF 35 4C 20 40 00 E8 D2 00 00 00 6A 00 E8 BF 00 00 00 99 68 58 20 40 00 52 52 68 63 10 40 00 52 52 E8 DB 00 00 00 6A FF FF 35 48 20 40 00 E8 C2 00 00 00 E8 C8 FF FF FF BF 40 40 40 00 FF 35 4C 20 40 00 E8 A1 00 00 00 8B 0F 83 F9 00 74 B1 60 6A 00 6A 04 6A 01 51 FF 35 48 20 40 00 E8 75 00 00 00 61 60 BB 5C 20 40 00 6A 00 6A 01 53 51 FF 35 48 20 40 00 E8 75 00 00 00 61 A0 5C 20 40 00 8A 5F 05 3A C3 74 14 FF 35 4C 20 40 00 E8 4B 00 00 00 6A 03 E8 4A 00 00 00 EB A2 60 8D 5F 04 6A 00 6A 01 53 51 FF 35 48 20 40 00 E8 4B 00 00 00 61 83 C7 06 FF 35 4C 20 40 00 E8 1E 00 00 00 6A 03 E8 1D 00 00 00 E9 72 FF FF FF FF 25 70 30 40 00 FF 25 78 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EP_v10
{
    meta:
        description = "EP v1.0"

    strings:
        $pattern = { 50 83 C0 17 8B F0 97 33 C0 33 C9 B1 24 AC 86 C4 AC AA 86 C4 AA E2 F6 00 B8 40 00 03 00 3C 40 D2 33 8B 66 14 50 70 8B 8D 34 02 44 8B 18 10 48 70 03 BA 0C ?? ?? ?? ?? C0 33 FE 8B 30 AC 30 D0 C1 F0 10 C2 D0 30 F0 30 C2 C1 AA 10 42 42 CA C1 E2 04 5F E9 5E B1 C0 30 ?? 68 ?? ?? F3 00 C3 AA }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EP_v20
{
    meta:
        description = "EP v2.0"

    strings:
        $pattern = { 6A ?? 60 E9 01 01 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ExeBundle_v30_standard_loader
{
    meta:
        description = "ExeBundle v3.0 (standard loader)"

    strings:
        $pattern = { 00 00 00 00 60 BE 00 B0 42 00 8D BE 00 60 FD FF C7 87 B0 E4 02 00 31 3C 4B DF 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ExeBundle_v30_small_loader
{
    meta:
        description = "ExeBundle v3.0 (small loader)"

    strings:
        $pattern = { 00 00 00 00 60 BE 00 F0 40 00 8D BE 00 20 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Exe_Shield_vxx
{
    meta:
        description = "Exe Shield vx.x"

    strings:
        $pattern = { 65 78 65 73 68 6C 2E 64 6C 6C C0 5D 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Exe_Shield_v17
{
    meta:
        description = "Exe Shield v1.7"

    strings:
        $pattern = { EB 06 68 90 1F 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Exe_Shield_v27
{
    meta:
        description = "Exe Shield v2.7"

    strings:
        $pattern = { EB 06 68 F4 86 06 00 C3 9C 60 E8 02 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Exe_Shield_v27b
{
    meta:
        description = "Exe Shield v2.7b"

    strings:
        $pattern = { EB 06 68 40 85 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 00 87 DD 8B 85 E6 90 40 00 01 85 33 90 40 00 66 C7 85 30 90 40 00 90 90 01 85 DA 90 40 00 01 85 DE 90 40 00 01 85 E2 90 40 00 BB 7B 11 00 00 03 9D EA 90 40 00 03 9D E6 90 40 00 53 8B C3 8B FB 2D AC 90 40 00 89 85 AD 90 40 00 8D B5 AC 90 40 00 B9 40 04 00 00 F3 A5 8B FB C3 BD 00 00 00 00 8B F7 83 C6 54 81 C7 FF 10 00 00 56 57 57 56 FF 95 DA 90 40 00 8B C8 5E 5F 8B C1 C1 F9 02 F3 A5 03 C8 83 E1 03 F3 A4 EB 26 D0 12 5B 00 AC 12 5B 00 48 12 5B 00 00 00 40 00 00 D0 5A 00 00 10 5B 00 87 DB 87 DB 87 DB 87 DB 87 DB 87 DB 87 DB 8B 0E B5 E6 90 40 07 56 03 76 EE 0F 18 83 C6 14 12 35 97 80 8D BD 63 39 0D B9 06 86 02 07 F3 A5 6A 04 68 06 10 12 1B FF B5 51 29 EE 10 22 95 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Exe_Shield_v29
{
    meta:
        description = "Exe Shield v2.9"

    strings:
        $pattern = { 60 E8 00 00 00 00 5D 81 ED 0B 20 40 00 B9 EB 08 00 00 8D BD 53 20 40 00 8B F7 AC ?? ?? ?? F8 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EXE_Stealth_v11
{
    meta:
        description = "EXE Stealth v1.1"

    strings:
        $pattern = { 60 E8 00 00 00 00 5D 81 ED FB 1D 40 00 B9 7B 09 00 00 8B F7 AC }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EXE_Stealth_v25
{
    meta:
        description = "EXE Stealth v2.5"

    strings:
        $pattern = { 60 90 EB 22 45 78 65 53 74 65 61 6C 74 68 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D E8 00 00 00 00 5D 81 ED 40 1E 40 00 B9 99 09 00 00 8D BD 88 1E 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EXE_Stealth_v27
{
    meta:
        description = "EXE Stealth v2.7"

    strings:
        $pattern = { EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED D3 26 40 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EXE_Stealth_v271
{
    meta:
        description = "EXE Stealth v2.71"

    strings:
        $pattern = { EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED B0 27 40 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EXE_Stealth_v272
{
    meta:
        description = "EXE Stealth v2.72"

    strings:
        $pattern = { EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EXE_Stealth_v273
{
    meta:
        description = "EXE Stealth v2.73"

    strings:
        $pattern = { EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 EB 16 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 00 60 90 E8 00 00 00 00 5D 81 ED F0 27 40 00 B9 15 00 00 00 83 C1 05 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 77 0C 00 00 90 8D BD 61 28 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EXE_Stealth_v274
{
    meta:
        description = "EXE Stealth v2.74"

    strings:
        $pattern = { EB 00 EB 17 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 60 90 E8 00 00 00 00 5D 81 ED C4 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 91 0C 00 00 90 8D BD 38 28 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EXE32Pack_v136
{
    meta:
        description = "EXE32Pack v1.36"

    strings:
        $pattern = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED CC 8D 40 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EXE32Pack_v137
{
    meta:
        description = "EXE32Pack v1.37"

    strings:
        $pattern = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED 4C 8E 40 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EXE32Pack_v138
{
    meta:
        description = "EXE32Pack v1.38"

    strings:
        $pattern = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED DC 8D 40 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EXE32Pack_v139
{
    meta:
        description = "EXE32Pack v1.39"

    strings:
        $pattern = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED EC 8D 40 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EXE32Pack_v13x
{
    meta:
        description = "EXE32Pack v1.3x"

    strings:
        $pattern = { 3B ?? 74 02 81 83 55 3B ?? 74 02 81 ?? 53 3B ?? 74 01 ?? ?? ?? ?? ?? 02 81 ?? ?? E8 ?? ?? ?? ?? 3B 74 01 ?? 5D 8B D5 81 ED }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EXECryptor_v13045
{
    meta:
        description = "EXECryptor v1.3.0.45"

    strings:
        $pattern = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 }
        $pattern_1 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule EXECryptor_v1401
{
    meta:
        description = "EXECryptor v1.4.0.1"

    strings:
        $pattern = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 ?? ?? 00 31 C0 89 41 14 89 41 18 80 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EXECryptor_v151x
{
    meta:
        description = "EXECryptor v1.5.1.x"

    strings:
        $pattern = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 C1 ?? ?? ?? FE C3 31 C0 64 FF 30 64 89 20 CC C3 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EXECryptor_v153
{
    meta:
        description = "EXECryptor v1.5.3"

    strings:
        $pattern = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 ?? ?? 00 31 C0 89 41 14 89 41 18 80 A1 C1 00 00 00 FE C3 31 C0 64 FF 30 64 89 20 CC C3 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EXECryptor_vxxxx
{
    meta:
        description = "EXECryptor vx.x.x.x"

    strings:
        $pattern = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EXEJoiner_v10
{
    meta:
        description = "EXEJoiner v1.0"

    strings:
        $pattern = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 C6 00 5C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 E8 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ExeSmasher_vxx
{
    meta:
        description = "ExeSmasher vx.x"

    strings:
        $pattern = { 9C FE 03 ?? 60 BE ?? ?? 41 ?? 8D BE ?? 10 FF FF 57 83 CD FF EB 10 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule EZIP_v10
{
    meta:
        description = "EZIP v1.0"

    strings:
        $pattern = { E9 19 32 00 00 E9 7C 2A 00 00 E9 19 24 00 00 E9 FF 23 00 00 E9 1E 2E 00 00 E9 88 2E 00 00 E9 2C }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule FSG_v10
{
    meta:
        description = "FSG v1.0"

    strings:
        $pattern = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule FSG_v11
{
    meta:
        description = "FSG v1.1"

    strings:
        $pattern = { BB D0 01 40 ?? BF ?? 10 40 ?? BE ?? ?? ?? ?? FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule FSG_v12
{
    meta:
        description = "FSG v1.2"

    strings:
        $pattern = { 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 ?? 00 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule FSG_v13
{
    meta:
        description = "FSG v1.3"

    strings:
        $pattern = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 41 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 96 33 C9 41 FF 54 24 04 13 C9 FF 54 24 04 72 F4 C3 5F 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 52 FF FF FF 5F BB ?? ?? ?? ?? 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE ?? 74 EF FE }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule FSG_v131
{
    meta:
        description = "FSG v1.31"

    strings:
        $pattern = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80 A4 B6 80 FF D3 73 F9 33 C9 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule FSG_v133
{
    meta:
        description = "FSG v1.33"

    strings:
        $pattern = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 }
        $pattern_1 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule FSG_v20
{
    meta:
        description = "FSG v2.0"

    strings:
        $pattern = { 87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Feokt
{
    meta:
        description = "Feokt"

    strings:
        $pattern = { 89 25 A8 11 40 00 BF ?? ?? ?? 00 31 C0 B9 ?? ?? ?? 00 29 F9 FC F3 AA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? 00 00 BE ?? ?? 40 00 BF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule FixupPak_v120
{
    meta:
        description = "FixupPak v1.20"

    strings:
        $pattern = { 55 E8 00 00 00 00 5D 81 ED ?? ?? 00 00 BE 00 ?? 00 00 03 F5 BA 00 00 ?? ?? 2B D5 8B DD 33 C0 AC 3C 00 74 3D 3C 01 74 0E 3C 02 74 0E 3C 03 74 0D 03 D8 29 13 EB E7 66 AD EB F6 AD EB F3 AC 0F B6 C8 3C 00 74 06 3C 01 74 09 EB 0A 66 AD 0F B7 C8 EB 03 AD 8B C8 AC 0F B6 C0 03 D8 29 13 E2 FA EB BC 8D 85 ?? ?? 00 00 5D FF E0 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Gleam_v100
{
    meta:
        description = "Gleam v1.00"

    strings:
        $pattern = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 EC 0C 53 56 57 E8 24 02 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Guardant_Stealth_aka_Novex_Dongle
{
    meta:
        description = "Guardant Stealth aka Novex Dongle"

    strings:
        $pattern = { 55 8B EC 83 C4 F0 60 E8 51 FF FF FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule GP_Install_v50332
{
    meta:
        description = "GP-Install v5.0.3.32"

    strings:
        $pattern = { 55 8B EC 33 C9 51 51 51 51 51 51 51 53 56 57 B8 C4 1C 41 00 E8 6B 3E FF FF 33 C0 55 68 76 20 41 00 64 FF 30 64 89 20 BA A0 47 41 00 33 C0 E8 31 0A FF FF 33 D2 A1 A0 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Hasp_dongle_Alladin
{
    meta:
        description = "Hasp dongle (Alladin)"

    strings:
        $pattern = { 50 53 51 52 57 56 8B 75 1C 8B 3E ?? ?? ?? ?? ?? 8B 5D 08 8A FB ?? ?? 03 5D 10 8B 45 0C 8B 4D 14 8B 55 18 80 FF 32 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Hasp_4_envelope_dongle_Alladin
{
    meta:
        description = "Hasp 4 envelope dongle (Alladin)"

    strings:
        $pattern = { 10 02 D0 51 0F 00 83 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Hardlock_dongle_Alladin
{
    meta:
        description = "Hardlock dongle (Alladin)"

    strings:
        $pattern = { 5C 5C 2E 5C 48 41 52 44 4C 4F 43 4B 2E 56 58 44 00 00 00 00 5C 5C 2E 5C 46 45 6E 74 65 44 65 76 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule iPBProtect_v013
{
    meta:
        description = "iPBProtect v0.1.3"

    strings:
        $pattern = { 55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 FA 33 DB 89 5D F8 6A 02 EB 01 F8 58 5F 5E 5B 64 8B 25 00 00 00 00 64 8F 05 00 00 00 00 58 58 58 5D 68 9F 6F 56 B6 50 E8 5D 00 00 00 EB FF 71 78 C2 50 00 EB D3 5B F3 68 89 5C 24 48 5C 24 58 FF 8D 5C 24 58 5B 83 C3 4C 75 F4 5A 8D 71 78 75 09 81 F3 EB FF 52 BA 01 00 83 EB FC 4A FF 71 0F 75 19 8B 5C 24 00 00 81 33 50 53 8B 1B 0F FF C6 75 1B 81 F3 EB 87 1C 24 8B 8B 04 24 83 EC FC EB 01 E8 83 EC FC E9 E7 00 00 00 58 EB FF F0 EB FF C0 83 E8 FD EB FF 30 E8 C9 00 00 00 89 E0 EB FF D0 EB FF 71 0F 83 C0 01 EB FF 70 F0 71 EE EB FA EB 83 C0 14 EB FF 70 ED 71 EB EB FA FF 83 C0 FC EB FF 70 ED 71 EB EB FA 0F 83 C0 F8 EB FF 70 ED 71 EB EB FA FF 83 C0 18 EB FF 70 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Inno_Setup_Module
{
    meta:
        description = "Inno Setup Module"

    strings:
        $pattern = { 49 6E 6E 6F 53 65 74 75 70 4C 64 72 57 69 6E 64 6F 77 00 00 53 54 41 54 49 43 }
        $pattern_1 = { 49 6E 6E 6F }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Inno_Setup_Module_v109a
{
    meta:
        description = "Inno Setup Module v1.09a"

    strings:
        $pattern = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 A7 7F FF FF E8 FA 92 FF FF E8 F1 B3 FF FF 33 C0 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Inno_Setup_Module_v129
{
    meta:
        description = "Inno Setup Module v1.2.9"

    strings:
        $pattern = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 EC 89 45 C0 E8 5B 73 FF FF E8 D6 87 FF FF E8 C5 A9 FF FF E8 E0 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Inno_Setup_Module_v2018
{
    meta:
        description = "Inno Setup Module v2.0.18"

    strings:
        $pattern = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 73 71 FF FF E8 DA 85 FF FF E8 81 A7 FF FF E8 C8 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Inno_Setup_Module_v304_beta_v306_v307
{
    meta:
        description = "Inno Setup Module v3.0.4-beta/v3.0.6/v3.0.7"

    strings:
        $pattern = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 B3 70 FF FF E8 1A 85 FF FF E8 25 A7 FF FF E8 6C }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Install_Stub_32_bit
{
    meta:
        description = "Install Stub 32-bit"

    strings:
        $pattern = { 55 8B EC 81 EC 14 ?? 00 00 53 56 57 6A 00 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 29 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule InstallShield_2000
{
    meta:
        description = "InstallShield 2000"

    strings:
        $pattern = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 C4 ?? 53 56 57 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule JDPack
{
    meta:
        description = "JDPack"

    strings:
        $pattern = { 60 E8 ?? ?? ?? ?? 5D 8B D5 81 ED ?? ?? ?? ?? 2B 95 ?? ?? ?? ?? 81 EA 06 ?? ?? ?? 89 95 ?? ?? ?? ?? 83 BD 45 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule kryptor_3
{
    meta:
        description = "kryptor 3"

    strings:
        $pattern = { EB 66 87 DB }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule kryptor_5
{
    meta:
        description = "kryptor 5"

    strings:
        $pattern = { E8 03 ?? ?? ?? E9 EB 6C 58 40 FF E0 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule kryptor_6
{
    meta:
        description = "kryptor 6"

    strings:
        $pattern = { E8 03 ?? ?? ?? E9 EB 68 58 33 D2 74 02 E9 E9 40 42 75 02 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule kryptor_8
{
    meta:
        description = "kryptor 8"

    strings:
        $pattern = { EB 6A 87 DB }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule kryptor_9
{
    meta:
        description = "kryptor 9"

    strings:
        $pattern = { 60 E8 ?? ?? ?? ?? 5E B9 ?? ?? ?? ?? 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 ?? 66 B9 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Krypton_v02
{
    meta:
        description = "Krypton v0.2"

    strings:
        $pattern = { 8B 0C 24 E9 0A 7C 01 ?? AD 42 40 BD BE 9D 7A 04 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Krypton_v03
{
    meta:
        description = "Krypton v0.3"

    strings:
        $pattern = { 8B 0C 24 E9 C0 8D 01 ?? C1 3A 6E CA 5D 7E 79 6D B3 64 5A 71 EA }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Krypton_v04
{
    meta:
        description = "Krypton v0.4"

    strings:
        $pattern = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 61 34 ?? ?? 2B 85 60 37 ?? ?? 83 E8 06 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Krypton_v05
{
    meta:
        description = "Krypton v0.5"

    strings:
        $pattern = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 71 44 ?? ?? 2B 85 64 60 ?? ?? EB 43 DF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule KGCrypt_vxx
{
    meta:
        description = "KGCrypt vx.x"

    strings:
        $pattern = { E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 64 A1 30 ?? ?? ?? 84 C0 74 ?? 64 A1 20 ?? ?? ?? 0B C0 74 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule LameCrypt_v10
{
    meta:
        description = "LameCrypt v1.0"

    strings:
        $pattern = { 60 66 9C BB ?? ?? ?? ?? 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule LTC_v13
{
    meta:
        description = "LTC v1.3"

    strings:
        $pattern = { 54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Lockless_Intro_Pack
{
    meta:
        description = "Lockless Intro Pack"

    strings:
        $pattern = { 2C E8 ?? ?? ?? ?? 5D 8B C5 81 ED F6 73 ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 06 89 85 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule LaunchAnywhere_v4001
{
    meta:
        description = "LaunchAnywhere v4.0.0.1"

    strings:
        $pattern = { 55 89 E5 53 83 EC 48 55 B8 FF FF FF FF 50 50 68 E0 3E 42 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 C0 69 44 00 E8 E4 80 FF FF 59 E8 4E 29 00 00 E8 C9 0D 00 00 85 C0 75 08 6A FF E8 6E 2B 00 00 59 E8 A8 2C 00 00 E8 23 2E 00 00 FF 15 4C C2 44 00 89 C3 EB 19 3C 22 75 14 89 C0 8D 40 00 43 8A 03 84 C0 74 04 3C 22 75 F5 3C 22 75 01 43 8A 03 84 C0 74 0B 3C 20 74 07 3C 09 75 D9 EB 01 43 8A 03 84 C0 74 04 3C 20 7E F5 8D 45 B8 50 FF 15 E4 C1 44 00 8B 45 E4 25 01 00 00 00 74 06 0F B7 45 E8 EB 05 B8 0A 00 00 00 50 53 6A 00 6A 00 FF 15 08 C2 44 00 50 E8 63 15 FF FF 50 E8 EE 2A 00 00 59 8D 65 FC 5B }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Launcher_Generator_v103
{
    meta:
        description = "Launcher Generator v1.03"

    strings:
        $pattern = { 68 00 20 40 00 68 10 20 40 00 6A 00 6A 00 6A 20 6A 00 6A 00 6A 00 68 F0 22 40 00 6A 00 E8 93 00 00 00 85 C0 0F 84 7E 00 00 00 B8 00 00 00 00 3B 05 68 20 40 00 74 13 6A ?? 68 60 23 40 00 68 20 23 40 00 6A 00 E8 83 00 00 00 A1 58 20 40 00 3B 05 6C 20 40 00 74 51 C1 E0 02 A3 5C 20 40 00 BB 70 21 40 00 03 C3 8B 18 68 60 20 40 00 53 B8 F0 21 40 00 03 05 5C 20 40 00 8B D8 8B 03 05 70 20 40 00 50 B8 70 22 40 00 03 05 5C 20 40 00 FF 30 FF 35 00 20 40 00 E8 26 00 00 00 A1 58 20 40 00 40 A3 58 20 40 00 EB A2 6A FF E8 00 00 00 00 FF 25 5C 30 40 00 FF 25 60 30 40 00 FF 25 64 30 40 00 FF 25 68 30 40 00 FF 25 6C 30 40 00 FF 25 74 30 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule MSLRH_v031a
{
    meta:
        description = "MSLRH v0.31a"

    strings:
        $pattern = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 0F C0 C9 D2 D1 0F C1 C0 D3 DA C0 D6 A8 EB 01 DE D0 EC 0F C1 CB D0 CF 0F C1 D1 D2 DB 0F C8 EB 01 BC C0 E9 C6 C1 D0 91 0F CB EB 01 73 0F CA 87 D9 87 D2 D0 CF 87 D9 0F C8 EB 01 C1 EB 01 A2 86 CA D0 E1 0F C0 CB 0F CA C0 C7 91 0F CB C1 D9 0C 86 F9 86 D7 D1 D9 EB 01 A5 EB 01 11 EB 01 1D 0F C1 C2 0F CB 0F C1 C2 EB 01 A1 C0 E9 FD 0F C1 D1 EB 01 E3 0F CA 87 D9 EB 01 F3 0F CB 87 C2 0F C0 F9 D0 F7 EB 01 2F 0F C9 C0 DC C4 EB 01 35 0F CA D3 D1 86 C8 EB 01 01 0F C0 F5 87 C8 D0 DE EB 01 95 EB 01 E1 EB 01 FD EB 01 EC 87 D3 0F CB C1 DB 35 D3 E2 0F C8 86 E2 86 EC C1 FB 12 D2 EE 0F C9 D2 F6 0F CA 87 C3 C1 D3 B3 EB 01 BF D1 CB 87 C9 0F CA 0F C1 DB EB 01 44 C0 CA F2 0F C1 D1 0F CB EB 01 D3 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Microsoft_CAB_SFX_module
{
    meta:
        description = "Microsoft CAB SFX module"

    strings:
        $pattern = { 55 8B EC 83 EC 44 56 FF 15 ?? 10 00 01 8B F0 8A 06 3C 22 75 14 8A 46 01 46 84 C0 74 04 3C 22 75 F4 80 3E 22 75 0D ?? EB 0A 3C 20 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Microsoft_Windows_Update_CAB_SFX_module
{
    meta:
        description = "Microsoft Windows Update CAB SFX module"

    strings:
        $pattern = { E9 C5 FA FF FF 55 8B EC 56 8B 75 08 68 04 08 00 00 FF D6 59 33 C9 3B C1 75 0F 51 6A 05 FF 75 28 E8 2E 11 00 00 33 C0 EB 69 8B 55 0C 83 88 88 00 00 00 FF 83 88 84 00 00 00 FF 89 50 04 8B 55 10 89 50 0C 8B 55 14 89 50 10 8B 55 18 89 50 14 8B 55 1C 89 50 18 8B 55 20 89 50 1C 8B 55 24 89 50 20 8B 55 28 89 48 48 89 48 44 89 48 4C B9 FF FF 00 00 89 70 08 89 10 66 C7 80 B2 00 00 00 0F 00 89 88 A0 00 00 00 89 88 A8 00 00 00 89 88 A4 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Macromedia_Windows_Flash_Projector_Player_v30
{
    meta:
        description = "Macromedia Windows Flash Projector/Player v3.0"

    strings:
        $pattern = { 55 8B EC 83 EC 44 56 FF 15 94 13 42 00 8B F0 B1 22 8A 06 3A C1 75 13 8A 46 01 46 3A C1 74 04 84 C0 75 F4 38 0E 75 0D 46 EB 0A 3C 20 7E 06 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Macromedia_Windows_Flash_Projector_Player_v40
{
    meta:
        description = "Macromedia Windows Flash Projector/Player v4.0"

    strings:
        $pattern = { 83 EC 44 56 FF 15 24 41 43 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Macromedia_Windows_Flash_Projector_Player_v50
{
    meta:
        description = "Macromedia Windows Flash Projector/Player v5.0"

    strings:
        $pattern = { 83 EC 44 56 FF 15 70 61 44 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C 3C 20 7E 08 8A 46 01 46 3C 20 7F F8 8A 06 84 C0 74 0C 3C 20 7F 08 8A 46 01 46 84 C0 75 F4 8D 44 24 04 C7 44 24 30 00 00 00 00 50 FF 15 80 61 44 00 F6 44 24 30 01 74 0B 8B 44 24 34 25 FF FF 00 00 EB 05 B8 0A 00 00 00 50 56 6A 00 6A 00 FF 15 74 61 44 00 50 E8 18 00 00 00 50 FF 15 78 61 44 00 5E 83 C4 44 C3 90 90 90 90 90 90 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Macromedia_Windows_Flash_Projector_Player_v60
{
    meta:
        description = "Macromedia Windows Flash Projector/Player v6.0"

    strings:
        $pattern = { 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule MEW_10_by_Northfox
{
    meta:
        description = "MEW 10 by Northfox"

    strings:
        $pattern = { 33 C0 E9 ?? ?? FF FF ?? 1C ?? ?? 40 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule MEW_11_SE_v11_by_Northfox
{
    meta:
        description = "MEW 11 SE v1.1 by Northfox"

    strings:
        $pattern = { E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule MEW_11_SE_v12_by_Northfox
{
    meta:
        description = "MEW 11 SE v1.2 by Northfox"

    strings:
        $pattern = { E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $pattern_1 = { E9 ?? ?? ?? FF 0C ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? ?? }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Morphine_v12___v13
{
    meta:
        description = "Morphine v1.2 - v1.3"

    strings:
        $pattern = { FF 25 34 ?? 5A 00 8B C0 FF 25 38 ?? 5A 00 8B C0 }
        $pattern_1 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? 00 00 00 66 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 51 66 ?? ?? ?? 59 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E2 ?? ?? ?? ?? ?? 82 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Morphine_v12_DLL
{
    meta:
        description = "Morphine v1.2 (DLL)"

    strings:
        $pattern = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 5B ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Neolite_v20
{
    meta:
        description = "Neolite v2.0"

    strings:
        $pattern = { E9 A6 00 00 00 }
        $pattern_1 = { E9 A6 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 4E 65 6F 4C 69 74 65 20 45 78 65 63 75 74 61 62 6C 65 20 46 69 6C 65 20 43 6F 6D 70 72 65 73 73 6F 72 0D 0A 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 38 2C 31 39 39 39 20 4E 65 6F 57 6F 72 78 20 49 6E 63 0D 0A 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule NeoLite_v20
{
    meta:
        description = "NeoLite v2.0"

    strings:
        $pattern = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9E 37 00 00 ?? ?? 48 ?? ?? ?? 6F 4C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 61 }
        $pattern_1 = { E9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4E 65 6F 4C 69 74 65 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule NeoLite_v10
{
    meta:
        description = "NeoLite v1.0"

    strings:
        $pattern = { E9 9B 00 00 00 A0 }
        $pattern_1 = { 8B 44 24 04 8D 54 24 FC 23 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 FF 25 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule NeoLite_v200
{
    meta:
        description = "NeoLite v2.00"

    strings:
        $pattern = { E9 A6 }
        $pattern_1 = { 8B 44 24 04 23 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 04 FE 05 ?? ?? ?? ?? 0B C0 74 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule NFO_v10
{
    meta:
        description = "NFO v1.0"

    strings:
        $pattern = { 8D 50 12 2B C9 B1 1E 8A 02 34 77 88 02 42 E2 F7 C8 8C }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule NFO_v1x_modified
{
    meta:
        description = "NFO v1.x modified"

    strings:
        $pattern = { 60 9C 8D 50 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule NoodleCrypt_v20
{
    meta:
        description = "NoodleCrypt v2.0"

    strings:
        $pattern = { EB 01 9A E8 ?? 00 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule North_Star_PE_Shrinker_v13_by_Liuxingping
{
    meta:
        description = "North Star PE Shrinker v1.3 by Liuxingping"

    strings:
        $pattern = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 73 ?? FF FF 8B 06 83 F8 00 74 11 8D B5 7F ?? FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 4F ?? FF FF 2B D0 89 95 4F ?? FF FF 01 95 67 ?? FF FF 8D B5 83 ?? FF FF 01 16 8B 36 8B FD 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 A3 ?? FF FF 85 C0 0F 84 06 03 00 00 89 85 63 ?? FF FF E8 00 00 00 00 5B B9 31 89 40 00 81 E9 2E 86 40 00 03 D9 50 53 E8 3D 02 00 00 61 03 BD 47 ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 2D 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 A7 ?? FF FF FF B5 A3 ?? FF FF 56 57 FF 95 63 ?? FF FF 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB CE 68 00 80 00 00 6A 00 FF B5 63 ?? FF FF FF 95 A7 ?? FF FF 8D }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Nullsoft_Install_System_v1xx
{
    meta:
        description = "Nullsoft Install System v1.xx"

    strings:
        $pattern = { 55 8B EC 83 EC 2C 53 56 33 F6 57 56 89 75 DC 89 75 F4 BB A4 9E 40 00 FF 15 60 70 40 00 BF C0 B2 40 00 68 04 01 00 00 57 50 A3 AC B2 40 00 FF 15 4C 70 40 00 56 56 6A 03 56 6A 01 68 00 00 00 80 57 FF 15 9C 70 40 00 8B F8 83 FF FF 89 7D EC 0F 84 C3 00 00 00 56 56 56 89 75 E4 E8 C1 C9 FF FF 8B 1D 68 70 40 00 83 C4 0C 89 45 E8 89 75 F0 6A 02 56 6A FC 57 FF D3 89 45 FC 8D 45 F8 56 50 8D 45 E4 6A 04 50 57 FF 15 48 70 40 00 85 C0 75 07 BB 7C 9E 40 00 EB 7A 56 56 56 57 FF D3 39 75 FC 7E 62 BF 74 A2 40 00 B8 00 10 00 00 39 45 FC 7F 03 8B 45 FC 8D 4D F8 56 51 50 57 FF 75 EC FF 15 48 70 40 00 85 C0 74 5A FF 75 F8 57 FF 75 E8 E8 4D C9 FF FF 89 45 E8 8B 45 F8 29 45 FC 83 C4 0C 39 75 F4 75 11 57 E8 D3 F9 FF FF 85 C0 59 74 06 8B 45 F0 89 45 F4 8B 45 F8 01 45 F0 39 75 FC }
        $pattern_1 = { 83 EC 0C 53 56 57 FF 15 20 71 40 00 05 E8 03 00 00 BE 60 FD 41 00 89 44 24 10 B3 20 FF 15 28 70 40 00 68 00 04 00 00 FF 15 28 71 40 00 50 56 FF 15 08 71 40 00 80 3D 60 FD 41 00 22 75 08 80 C3 02 BE 61 FD 41 00 8A 06 8B 3D F0 71 40 00 84 C0 74 0F 3A C3 74 0B 56 FF D7 8B F0 8A 06 84 C0 75 F1 80 3E 00 74 05 56 FF D7 8B F0 89 74 24 14 80 3E 20 75 07 56 FF D7 8B F0 EB F4 80 3E 2F 75 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Nullsoft_Install_System_v198
{
    meta:
        description = "Nullsoft Install System v1.98"

    strings:
        $pattern = { 83 EC 0C 53 56 57 FF 15 2C 81 40 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Nullsoft_Install_System_v20a0
{
    meta:
        description = "Nullsoft Install System v2.0a0"

    strings:
        $pattern = { 83 EC 0C 53 56 57 FF 15 B4 10 40 00 05 E8 03 00 00 BE E0 E3 41 00 89 44 24 10 B3 20 FF 15 28 10 40 00 68 00 04 00 00 FF 15 14 11 40 00 50 56 FF 15 10 11 40 00 80 3D E0 E3 41 00 22 75 08 80 C3 02 BE E1 E3 41 00 8A 06 8B 3D 14 12 40 00 84 C0 74 19 3A C3 74 0B 56 FF D7 8B F0 8A 06 84 C0 75 F1 80 3E 00 }
        $pattern_1 = { 83 EC 0C 53 55 56 57 C7 44 24 10 70 92 40 00 33 DB C6 44 24 14 20 FF 15 2C 70 40 00 53 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 2D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 68 68 92 40 00 56 FF D5 E8 6A FF FF FF 85 C0 0F 84 57 01 00 00 BE 20 E4 42 00 56 FF 15 68 70 40 00 68 5C 92 40 00 56 E8 9C 28 00 00 57 FF 15 BC 70 40 00 BE 00 40 43 00 50 56 FF 15 B8 70 40 00 6A 00 FF 15 44 71 40 00 80 3D 00 40 43 00 22 A3 20 EC 42 00 75 0A C6 44 24 14 22 BE 01 40 43 00 FF 74 24 14 56 E8 8A 23 00 00 50 FF 15 80 71 40 00 8B F8 89 7C 24 18 EB 61 80 F9 20 75 06 40 80 38 20 74 FA 80 38 22 C6 44 24 14 20 75 06 40 C6 44 24 14 22 80 38 2F 75 31 40 80 38 53 75 0E 8A 48 01 80 C9 20 80 F9 20 75 03 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Nullsoft_Install_System_v20b2_v20b3
{
    meta:
        description = "Nullsoft Install System v2.0b2, v2.0b3"

    strings:
        $pattern = { 83 EC 0C 53 55 56 57 FF 15 ?? 70 40 00 8B 35 ?? 92 40 00 05 E8 03 00 00 89 44 24 14 B3 20 FF 15 2C 70 40 00 BF 00 04 00 00 68 ?? ?? ?? 00 57 FF 15 ?? ?? 40 00 57 FF 15 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Nullsoft_Install_System_v20b4
{
    meta:
        description = "Nullsoft Install System v2.0b4"

    strings:
        $pattern = { 83 EC 10 53 55 56 57 C7 44 24 14 F0 91 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 88 72 40 00 BE 00 D4 42 00 BF 00 04 00 00 56 57 A3 60 6F 42 00 FF 15 C4 70 40 00 E8 9F FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 60 71 40 00 68 E4 91 40 00 56 FF D3 E8 7C FF FF FF 85 C0 0F 84 59 01 00 00 BE E0 66 42 00 56 FF 15 68 70 40 00 68 D8 91 40 00 56 E8 FE 27 00 00 57 FF 15 BC 70 40 00 BE 00 C0 42 00 50 56 FF 15 B8 70 40 00 6A 00 FF 15 44 71 40 00 80 3D 00 C0 42 00 22 A3 E0 6E 42 00 8B C6 75 0A C6 44 24 13 22 B8 01 C0 42 00 8B 3D 10 72 40 00 EB 09 3A 4C 24 13 74 09 50 FF D7 8A 08 84 C9 75 F1 50 FF D7 8B F0 89 74 24 1C EB 05 56 FF D7 8B F0 80 3E 20 74 F6 80 3E 2F 75 44 46 80 3E 53 75 0C 8A 46 01 0C 20 3C 20 75 03 83 CD 02 81 3E 4E 43 52 }
        $pattern_1 = { 83 EC 14 83 64 24 04 00 53 55 56 57 C6 44 24 13 20 FF 15 30 70 40 00 BE 00 20 7A 00 BD 00 04 00 00 56 55 FF 15 C4 70 40 00 56 E8 7D 2B 00 00 8B 1D 8C 70 40 00 6A 00 56 FF D3 BF 80 92 79 00 56 57 E8 15 26 00 00 85 C0 75 38 68 F8 91 40 00 55 56 FF 15 60 71 40 00 03 C6 50 E8 78 29 00 00 56 E8 47 2B 00 00 6A 00 56 FF D3 56 57 E8 EA 25 00 00 85 C0 75 0D C7 44 24 14 58 91 40 00 E9 72 02 00 00 57 FF 15 24 71 40 00 68 EC 91 40 00 57 E8 43 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Nullsoft_Install_System_v20_RC2
{
    meta:
        description = "Nullsoft Install System v2.0 RC2"

    strings:
        $pattern = { 83 EC 10 53 55 56 57 C7 44 24 14 70 92 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 68 68 92 40 00 56 FF D3 E8 6A FF FF FF 85 C0 0F 84 59 01 00 00 BE 20 E4 42 00 56 FF 15 68 70 40 00 68 5C 92 40 00 56 E8 B9 28 00 00 57 FF 15 BC 70 40 00 BE 00 40 43 00 50 56 FF 15 B8 70 40 00 6A 00 FF 15 44 71 40 00 80 3D 00 40 43 00 22 A3 20 EC 42 00 8B C6 75 0A C6 44 24 13 22 B8 01 40 43 00 8B 3D 18 72 40 00 EB 09 3A 4C 24 13 74 09 50 FF D7 8A 08 84 C9 75 F1 50 FF D7 8B F0 89 74 24 1C EB 05 56 FF D7 8B F0 80 3E 20 74 F6 80 3E 2F 75 44 46 80 3E 53 75 0C 8A 46 01 0C 20 3C 20 75 03 83 CD 02 81 3E 4E 43 52 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Nullsoft_PIMP_Install_System_v13x
{
    meta:
        description = "Nullsoft PIMP Install System v1.3x"

    strings:
        $pattern = { 55 8B EC 81 EC ?? ?? 00 00 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Nullsoft_PIMP_Install_System_v1x
{
    meta:
        description = "Nullsoft PIMP Install System v1.x"

    strings:
        $pattern = { 83 EC 5C 53 55 56 57 FF 15 ?? ?? ?? 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule NX_PE_Packer_v10
{
    meta:
        description = "NX PE Packer v1.0"

    strings:
        $pattern = { FF 60 FF CA FF 00 BA DC 0D E0 40 00 50 00 60 00 70 00 80 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Obsidium_v1111
{
    meta:
        description = "Obsidium v1.1.1.1"

    strings:
        $pattern = { EB 02 ?? ?? E8 E7 1C 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Obsidium_v10059_Final
{
    meta:
        description = "Obsidium v1.0.0.59 Final"

    strings:
        $pattern = { E8 AB 1C }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Obsidium_v10061
{
    meta:
        description = "Obsidium v1.0.0.61"

    strings:
        $pattern = { E8 AF 1C 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Obsidium_vxxxx
{
    meta:
        description = "Obsidium vx.x.x.x"

    strings:
        $pattern = { E8 47 19 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ORiEN_v211_DEMO
{
    meta:
        description = "ORiEN v2.11 (DEMO)"

    strings:
        $pattern = { E9 5D 01 00 00 CE D1 CE CE 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F 74 65 63 74 69 6F 6E 20 73 79 73 74 65 6D 20 2D 0D 0A 2D 2D 2D 2D 2D 2D 20 43 72 65 61 74 65 64 20 62 79 20 41 2E 20 46 69 73 75 6E 2C 20 31 39 39 34 2D 32 30 30 33 20 2D 2D 2D 2D 2D 2D 0D 0A 2D 2D 2D 2D 2D 2D 2D 20 57 57 57 3A 20 68 74 74 70 3A 2F 2F 7A 61 6C 65 78 66 2E 6E 61 72 6F 64 2E 72 75 2F 20 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 20 65 2D 6D 61 69 6C 3A 20 7A 61 6C 65 78 66 40 68 6F 74 6D 61 69 6C 2E 72 75 20 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Packman_v0001
{
    meta:
        description = "Packman v0.0.0.1"

    strings:
        $pattern = { 60 E8 00 00 00 00 58 8D A8 ?? ?? FF FF 8D 98 ?? ?? ?? FF 8D B0 74 01 00 00 8D 4E F6 48 C6 40 FB E9 8D 93 ?? ?? ?? 00 2B D0 89 50 FC 8D 93 54 01 00 00 E9 9A 00 00 00 83 C2 04 03 FB 51 D1 C7 D1 EF 0F 83 84 00 00 00 53 55 52 B2 80 8B D9 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 3D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 A4 5E EB 97 33 C9 41 FF D3 13 C9 FF D3 72 F8 C3 5A 5D 5B EB 05 AD 8B C8 F3 A4 59 8B 3A 85 FF 0F 85 5C FF FF FF 8D B3 ?? 20 ?? 00 EB 3D 8B 46 0C 03 C3 50 FF 55 00 56 8B 36 0B F6 75 02 8B F7 03 F3 03 FB EB 1B D1 C1 D1 E9 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Pack_Master_v10
{
    meta:
        description = "Pack Master v1.0"

    strings:
        $pattern = { 60 E8 01 ?? ?? ?? E8 83 C4 04 E8 01 ?? ?? ?? E9 5D 81 ED D3 22 40 ?? E8 04 02 ?? ?? E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 }
        $pattern_1 = { 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED D3 22 40 00 E8 04 02 00 00 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Patch_Creation_Wizard_v12_Byte_Patch
{
    meta:
        description = "Patch Creation Wizard v1.2 Byte Patch"

    strings:
        $pattern = { E8 7F 03 00 00 6A 00 E8 24 03 00 00 A3 B8 33 40 00 6A 00 68 29 10 40 00 6A 00 6A 01 50 E8 2C 03 00 00 6A 00 E8 EF 02 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 0F 85 C1 00 00 00 6A 01 FF 35 B8 33 40 00 E8 1B 03 00 00 50 6A 01 68 80 00 00 00 FF 75 08 E8 1D 03 00 00 68 5F 30 40 00 6A 65 FF 75 08 E8 14 03 00 00 68 B0 30 40 00 6A 67 FF 75 08 E8 05 03 00 00 68 01 31 40 00 6A 66 FF 75 08 E8 F6 02 00 00 6A 00 FF 75 08 E8 C8 02 00 00 A3 B4 33 40 00 C7 05 BC 33 40 00 2C 00 00 00 C7 05 C0 33 40 00 10 00 00 00 C7 05 C4 33 40 00 00 08 00 00 68 BC 33 40 00 6A 01 6A FF FF 35 B4 33 40 00 E8 97 02 00 00 C7 05 C4 33 40 00 00 00 00 00 C7 05 E0 33 40 00 00 30 40 00 C7 05 E4 33 40 00 01 00 00 00 68 BC 33 40 00 6A 01 6A FF FF 35 B4 33 40 00 E8 65 02 00 00 EB 5F EB 54 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Patch_Creation_Wizard_v12_Seek_and_Destroy_Patch
{
    meta:
        description = "Patch Creation Wizard v1.2 Seek and Destroy Patch"

    strings:
        $pattern = { E8 C5 05 00 00 6A 00 E8 5E 05 00 00 A3 CE 39 40 00 6A 00 68 29 10 40 00 6A 00 6A 01 50 E8 72 05 00 00 6A 00 E8 2F 05 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 0F 85 C1 00 00 00 6A 01 FF 35 CE 39 40 00 E8 61 05 00 00 50 6A 01 68 80 00 00 00 FF 75 08 E8 63 05 00 00 68 5F 30 40 00 6A 65 FF 75 08 E8 5A 05 00 00 68 B0 30 40 00 6A 67 FF 75 08 E8 4B 05 00 00 68 01 31 40 00 6A 66 FF 75 08 E8 3C 05 00 00 6A 00 FF 75 08 E8 0E 05 00 00 A3 CA 39 40 00 C7 05 D2 39 40 00 2C 00 00 00 C7 05 D6 39 40 00 10 00 00 00 C7 05 DA 39 40 00 00 08 00 00 68 D2 39 40 00 6A 01 6A FF FF 35 CA 39 40 00 E8 DD 04 00 00 C7 05 DA 39 40 00 00 00 00 00 C7 05 F6 39 40 00 00 30 40 00 C7 05 FA 39 40 00 01 00 00 00 68 D2 39 40 00 6A 01 6A FF FF 35 CA 39 40 00 E8 AB 04 00 00 EB 5F EB 54 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Patch_Creation_Wizard_v12_Memory_Patch
{
    meta:
        description = "Patch Creation Wizard v1.2 Memory Patch"

    strings:
        $pattern = { 6A 00 E8 9B 02 00 00 A3 7A 33 40 00 6A 00 68 8E 10 40 00 6A 00 6A 01 50 E8 B5 02 00 00 68 5A 31 40 00 68 12 31 40 00 6A 00 6A 00 6A 04 6A 01 6A 00 6A 00 68 A2 30 40 00 6A 00 E8 51 02 00 00 85 C0 74 31 FF 35 62 31 40 00 6A 00 6A 30 E8 62 02 00 00 E8 0B 01 00 00 FF 35 5A 31 40 00 E8 22 02 00 00 FF 35 5E 31 40 00 E8 53 02 00 00 6A 00 E8 22 02 00 00 6A 10 68 F7 30 40 00 68 FE 30 40 00 6A 00 E8 63 02 00 00 6A 00 E8 08 02 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 75 6B 6A 01 FF 35 7A 33 40 00 E8 38 02 00 00 50 6A 01 68 80 00 00 00 FF 75 08 E8 34 02 00 00 68 00 30 40 00 6A 65 FF 75 08 E8 2B 02 00 00 68 51 30 40 00 6A 67 FF 75 08 E8 1C 02 00 00 68 A2 30 40 00 6A 66 FF 75 08 E8 0D 02 00 00 8B 45 08 A3 7E 33 40 00 68 3B 11 40 00 68 E8 03 00 00 68 9A 02 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PC_PE_Encryptor_Alpha_preview
{
    meta:
        description = "PC PE Encryptor Alpha preview"

    strings:
        $pattern = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B CD 81 ED 33 30 40 ?? 2B 8D EE 32 40 00 83 E9 0B 89 8D F2 32 40 ?? 80 BD D1 32 40 ?? 01 0F 84 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PEEncrypt_v40b_JunkCode
{
    meta:
        description = "PEEncrypt v4.0b (JunkCode)"

    strings:
        $pattern = { 66 ?? ?? 00 66 83 ?? 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Crypt_v100_v101
{
    meta:
        description = "PE Crypt v1.00/v1.01"

    strings:
        $pattern = { E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Crypt_v102
{
    meta:
        description = "PE Crypt v1.02"

    strings:
        $pattern = { E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Crypt32_v102
{
    meta:
        description = "PE Crypt32 v1.02"

    strings:
        $pattern = { E8 00 00 00 00 5B 83 ?? ?? EB ?? 52 4E 44 21 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Crypt32_Console_v10_v101_v102
{
    meta:
        description = "PE Crypt32 (Console v1.0, v1.01, v1.02)"

    strings:
        $pattern = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Intro_v10
{
    meta:
        description = "PE Intro v1.0"

    strings:
        $pattern = { 8B 04 24 9C 60 E8 ?? ?? ?? ?? 5D 81 ED 0A 45 40 ?? 80 BD 67 44 40 ?? ?? 0F 85 48 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Lock_NT_v201
{
    meta:
        description = "PE Lock NT v2.01"

    strings:
        $pattern = { EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 9C EB 03 CD }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Lock_NT_v202c
{
    meta:
        description = "PE Lock NT v2.02c"

    strings:
        $pattern = { EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Lock_NT_v203
{
    meta:
        description = "PE Lock NT v2.03"

    strings:
        $pattern = { EB 02 C7 85 1E EB 03 CD 20 C7 9C EB 02 69 B1 60 EB 02 EB 01 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Lock_NT_v204
{
    meta:
        description = "PE Lock NT v2.04"

    strings:
        $pattern = { EB ?? CD ?? ?? ?? ?? ?? CD ?? ?? ?? ?? ?? EB ?? EB ?? EB ?? EB ?? CD ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 50 C3 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Lock_v106
{
    meta:
        description = "PE Lock v1.06"

    strings:
        $pattern = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 4B 45 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Pack_v099
{
    meta:
        description = "PE Pack v0.99"

    strings:
        $pattern = { 60 E8 ?? ?? ?? ?? 5D 83 ED 06 80 BD E0 04 ?? ?? 01 0F 84 F2 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Pack_v10
{
    meta:
        description = "PE Pack v1.0"

    strings:
        $pattern = { 74 ?? E9 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Packer
{
    meta:
        description = "PE Packer"

    strings:
        $pattern = { FC 8B 35 70 01 40 ?? 83 EE 40 6A 40 68 ?? 30 10 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Password_v02_SMT_SMF
{
    meta:
        description = "PE Password v0.2 SMT/SMF"

    strings:
        $pattern = { E8 04 ?? ?? ?? 8B EC 5D C3 33 C0 5D 8B FD 81 ED 33 26 40 ?? 81 EF ?? ?? ?? ?? 83 EF 05 89 AD 88 27 40 ?? 8D 9D 07 29 40 ?? 8D B5 62 28 40 ?? 46 80 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Protect_v09
{
    meta:
        description = "PE Protect v0.9"

    strings:
        $pattern = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 ?? ?? ?? ?? 58 83 C0 07 C6 ?? C3 }
        $pattern_1 = { E9 ?? 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39 20 28 43 29 6F 70 79 72 69 67 68 74 20 62 79 20 43 48 52 69 53 54 4F 50 48 20 47 41 42 4C 45 52 20 69 6E 20 31 39 39 38 21 0D 0A 52 65 67 69 73 74 65 72 65 64 20 74 6F 20 3A 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule PEQuake_v006_by_fORGAT
{
    meta:
        description = "PEQuake v0.06 by fORGAT"

    strings:
        $pattern = { E8 A5 00 00 00 2D ?? 00 00 00 00 00 00 00 00 00 00 3D ?? 00 00 2D ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4A ?? 00 00 5B ?? 00 00 6E ?? 00 00 00 00 00 00 6B 45 72 4E 65 4C 33 32 2E 64 4C 6C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 ?? ?? 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 5D 81 ED 05 00 00 00 8D 75 3D 56 FF 55 31 8D B5 81 00 00 00 56 50 FF 55 2D 89 85 8E 00 00 00 6A 04 68 00 10 00 00 68 ?? ?? 00 00 6A 00 FF 95 8E 00 00 00 50 8B 9D 7D 00 00 00 03 DD 50 53 E8 04 00 00 00 5A 55 FF E2 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PC_Shrinker_v020
{
    meta:
        description = "PC Shrinker v0.20"

    strings:
        $pattern = { E8 E8 01 ?? ?? 60 01 AD B3 27 40 ?? 68 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PC_Shrinker_v029
{
    meta:
        description = "PC Shrinker v0.29"

    strings:
        $pattern = { ?? BD ?? ?? ?? ?? 01 AD 55 39 40 ?? 8D B5 35 39 40 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PC_Shrinker_v045
{
    meta:
        description = "PC Shrinker v0.45"

    strings:
        $pattern = { ?? BD ?? ?? ?? ?? 01 AD E3 38 40 ?? FF B5 DF 38 40 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PC_Shrinker_v071
{
    meta:
        description = "PC Shrinker v0.71"

    strings:
        $pattern = { 9C 60 BD ?? ?? ?? ?? 01 AD 54 3A 40 ?? FF B5 50 3A 40 ?? 6A 40 FF 95 88 3A 40 ?? 50 50 2D ?? ?? ?? ?? 89 85 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PeStubOEP_v1x
{
    meta:
        description = "PeStubOEP v1.x"

    strings:
        $pattern = { ?? ?? B8 ?? ?? ?? 00 FF E0 }
        $pattern_1 = { E8 05 00 00 00 33 C0 40 48 C3 E8 05 }
        $pattern_2 = { 90 33 C9 33 D2 B8 ?? ?? ?? 00 B9 FF }
        $pattern_3 = { 90 ?? 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule PEStubOEP_v1x
{
    meta:
        description = "PEStubOEP v1.x"

    strings:
        $pattern = { 40 48 BE 00 ?? ?? 00 40 48 60 33 C0 B8 ?? ?? ?? 00 FF E0 C3 C3 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PC_Guard_v303d_v305d
{
    meta:
        description = "PC-Guard v3.03d, v3.05d"

    strings:
        $pattern = { 55 50 E8 ?? ?? ?? ?? 5D EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PC_Guard_v405d_v410d_v415d
{
    meta:
        description = "PC-Guard v4.05d, v4.10d, v4.15d"

    strings:
        $pattern = { FC 55 50 E8 00 00 00 00 5D EB 01 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PC_Guard_v500d
{
    meta:
        description = "PC-Guard v5.00d"

    strings:
        $pattern = { FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 30 D2 40 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B E8 9C EB 01 D5 9D EB 01 0B 58 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 89 85 E1 EA 41 00 9C EB 01 D5 9D EB 01 0B 58 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 89 85 F9 EA 41 00 9C EB 01 D5 9D EB 01 0B 89 9D E5 EA 41 00 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 89 8D E9 EA 41 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 89 95 ED EA 41 00 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 89 B5 F1 EA 41 00 9C EB 01 D5 9D EB 01 0B 89 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Crypter
{
    meta:
        description = "PE-Crypter"

    strings:
        $pattern = { 60 E8 00 00 00 00 5D EB 26 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PEBundle_v310
{
    meta:
        description = "PEBundle v3.10"

    strings:
        $pattern = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 00 87 DD ?? ?? ?? ?? 40 00 01 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PEBundle_v02___v20x
{
    meta:
        description = "PEBundle v0.2 - v2.0x"

    strings:
        $pattern = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PEBundle_v20b5___v23
{
    meta:
        description = "PEBundle v2.0b5 - v2.3"

    strings:
        $pattern = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 01 AD ?? ?? ?? ?? 01 AD }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PEBundle_v244
{
    meta:
        description = "PEBundle v2.44"

    strings:
        $pattern = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 83 BD }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v090
{
    meta:
        description = "PECompact v0.90"

    strings:
        $pattern = { EB 06 68 ?? ?? 40 00 C3 9C 60 BD ?? ?? 00 00 B9 02 00 00 00 B0 90 8D BD 7A 42 40 00 F3 AA 01 AD D9 43 40 00 FF B5 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v092
{
    meta:
        description = "PECompact v0.92"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD A5 4F 40 ?? F3 AA 01 AD 04 51 40 ?? FF B5 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v094
{
    meta:
        description = "PECompact v0.94"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v0971___v0976
{
    meta:
        description = "PECompact v0.971 - v0.976"

    strings:
        $pattern = { EB 06 68 C3 9C 60 E8 5D 55 5B 81 ED 8B 85 01 85 66 C7 85 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v0977
{
    meta:
        description = "PECompact v0.977"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB A0 86 40 ?? 87 DD 8B 85 2A 87 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v0978
{
    meta:
        description = "PECompact v0.978"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 24 88 40 ?? 87 DD 8B 85 A9 88 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v09781
{
    meta:
        description = "PECompact v0.978.1"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 49 87 40 ?? 87 DD 8B 85 CE 87 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v09782
{
    meta:
        description = "PECompact v0.978.2"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D1 84 40 ?? 87 DD 8B 85 56 85 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v098
{
    meta:
        description = "PECompact v0.98"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D7 84 40 ?? 87 DD 8B 85 5C 85 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v099
{
    meta:
        description = "PECompact v0.99"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 2F 85 40 ?? 87 DD 8B 85 B4 85 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v100
{
    meta:
        description = "PECompact v1.00"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB C4 84 40 ?? 87 DD 8B 85 49 85 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v110b1
{
    meta:
        description = "PECompact v1.10b1"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 28 63 40 ?? 87 DD 8B 85 AD 63 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v110b2
{
    meta:
        description = "PECompact v1.10b2"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 94 60 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v110b3
{
    meta:
        description = "PECompact v1.10b3"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 95 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v110b4
{
    meta:
        description = "PECompact v1.10b4"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 44 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v110b5
{
    meta:
        description = "PECompact v1.10b5"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 49 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v110b6
{
    meta:
        description = "PECompact v1.10b6"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 ?? 00 87 DD 8B 85 9A 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 01 85 92 60 40 ?? BB B7 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v110b7
{
    meta:
        description = "PECompact v1.10b7"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 9A 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 01 85 92 60 40 ?? BB 14 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v120___v1201
{
    meta:
        description = "PECompact v1.20 - v1.20.1"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 9A 70 40 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v122
{
    meta:
        description = "PECompact v1.22"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 ?? 70 40 ?? 90 90 01 85 9E 70 40 ?? BB F3 08 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v123b3___v1241
{
    meta:
        description = "PECompact v1.23b3 - v1.24.1"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? D2 08 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v1242___v1243
{
    meta:
        description = "PECompact v1.24.2 - v1.24.3"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? D2 09 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v125
{
    meta:
        description = "PECompact v1.25"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? F3 0D }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v126b1___v126b2
{
    meta:
        description = "PECompact v1.26b1 - v1.26b2"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? 05 0E }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v133
{
    meta:
        description = "PECompact v1.33"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A6 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 00 80 40 ?? 90 90 01 85 9E 80 40 ?? BB E8 0E }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v134___v140b1
{
    meta:
        description = "PECompact v1.34 - v1.40b1"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A6 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 00 80 ?? 40 90 90 01 85 9E 80 ?? 40 BB F8 10 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v140b2___v140b4
{
    meta:
        description = "PECompact v1.40b2 - v1.40b4"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 86 11 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v140b5___v140b6
{
    meta:
        description = "PECompact v1.40b5 - v1.40b6"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 8A 11 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v140___v145
{
    meta:
        description = "PECompact v1.40 - v1.45"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB C3 11 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v146
{
    meta:
        description = "PECompact v1.46"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 60 12 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v147___v150
{
    meta:
        description = "PECompact v1.47 - v1.50"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 5B 12 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v155
{
    meta:
        description = "PECompact v1.55"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A2 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 9E 80 40 ?? BB 2D 12 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v156
{
    meta:
        description = "PECompact v1.56"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 90 40 ?? 87 DD 8B 85 A2 90 40 ?? 01 85 03 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 9E 90 40 ?? BB 2D 12 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v160___v165
{
    meta:
        description = "PECompact v1.60 - v1.65"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 80 40 ?? 87 DD 8B 85 D2 80 40 ?? 01 85 33 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 CE 80 40 ?? BB BB 12 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v166
{
    meta:
        description = "PECompact v1.66"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 ?? 87 DD 8B 85 E6 90 40 ?? 01 85 33 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 DA 90 40 ?? 01 85 DE 90 40 ?? 01 85 E2 90 40 ?? BB 5B 11 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v167
{
    meta:
        description = "PECompact v1.67"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 87 DD 8B 85 E6 90 40 01 85 33 90 40 66 C7 85 90 40 90 90 01 85 DA 90 40 01 85 DE 90 40 01 85 E2 90 40 BB 8B 11 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v168___v184
{
    meta:
        description = "PECompact v1.68 - v1.84"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 87 DD 8B 85 E6 90 40 01 85 33 90 40 66 C7 85 90 40 90 90 01 85 DA 90 40 01 85 DE 90 40 01 85 E2 90 40 BB 7B 11 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v14xp
{
    meta:
        description = "PECompact v1.4x+"

    strings:
        $pattern = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v184
{
    meta:
        description = "PECompact v1.84"

    strings:
        $pattern = { 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v200_alpha_38
{
    meta:
        description = "PECompact v2.00 alpha 38"

    strings:
        $pattern = { B8 ?? ?? ?? ?? 80 B8 BF 10 00 10 01 74 7A C6 80 BF 10 00 10 01 9C 55 53 51 57 52 56 8D 98 0F 10 00 10 8B 53 14 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 8B 4B 10 03 CA 8B 01 FF D0 8B F8 50 8B 33 8B 53 14 03 F2 8B 4B 0C 03 CA 8D 85 B7 10 00 10 FF 73 04 8F 00 50 57 56 FF D1 58 03 43 08 8B F8 8B 53 14 8B F0 8B 46 FC 83 C0 04 2B F0 89 56 08 8B 4B 10 89 4E 18 FF D7 89 85 BB 10 00 10 5E 5A 5F 59 5B 5D 9D FF E0 8B 80 BB 10 00 10 FF E0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Diminisher_v01
{
    meta:
        description = "PE Diminisher v0.1"

    strings:
        $pattern = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B D5 81 ED A2 30 40 00 2B 95 91 33 40 00 81 EA 0B 00 00 00 89 95 9A 33 40 00 80 BD 99 33 40 00 00 74 }
        $pattern_1 = { 5D 8B D5 81 ED A2 30 40 ?? 2B 95 91 33 40 ?? 81 EA 0B ?? ?? ?? 89 95 9A 33 40 ?? 80 BD 99 }
        $pattern_2 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B D5 81 ED A2 30 40 00 2B 95 91 33 40 00 81 EA 0B 00 00 00 89 95 9A 33 40 00 80 BD 99 33 40 00 00 74 50 E8 02 01 00 00 8B FD 8D 9D 9A 33 40 00 8B 1B 8D 87 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule PEncrypt_v10
{
    meta:
        description = "PEncrypt v1.0"

    strings:
        $pattern = { 60 9C BE 00 10 40 00 8B FE B9 28 03 00 00 BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PEncrypt_v30
{
    meta:
        description = "PEncrypt v3.0"

    strings:
        $pattern = { E8 00 00 00 00 5D 81 ED 05 10 40 00 8D B5 24 10 40 00 8B FE B9 0F 00 00 00 BB ?? ?? ?? ?? AD 33 C3 E2 FA }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PEncrypt_v31
{
    meta:
        description = "PEncrypt v3.1"

    strings:
        $pattern = { E9 ?? ?? ?? 00 F0 0F C6 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PEnguinCrypt_v10
{
    meta:
        description = "PEnguinCrypt v1.0"

    strings:
        $pattern = { B8 93 ?? ?? 00 55 50 67 64 FF 36 00 00 67 64 89 26 00 00 BD 4B 48 43 42 B8 04 00 00 00 CC 3C 04 75 04 90 90 C3 90 67 64 8F 06 00 00 58 5D BB 00 00 40 00 33 C9 33 C0 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PENightMare_v13
{
    meta:
        description = "PENightMare v1.3"

    strings:
        $pattern = { 60 E8 00 00 00 00 5D B9 ?? ?? ?? ?? 80 31 15 41 81 F9 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PENightMare_2_Beta
{
    meta:
        description = "PENightMare 2 Beta"

    strings:
        $pattern = { 60 E9 ?? ?? ?? ?? EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PENinja
{
    meta:
        description = "PENinja"

    strings:
        $pattern = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PENinja_modified
{
    meta:
        description = "PENinja modified"

    strings:
        $pattern = { 5D 8B C5 81 ED B2 2C 40 00 2B 85 94 3E 40 00 2D 71 02 00 00 89 85 98 3E 40 00 0F B6 B5 9C 3E 40 00 8B FD }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PEMangle
{
    meta:
        description = "PEMangle"

    strings:
        $pattern = { 60 9C BE ?? ?? ?? ?? 8B FE B9 ?? ?? ?? ?? BB 44 52 4F 4C AD 33 C3 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PESHiELD_v01b_MTE
{
    meta:
        description = "PESHiELD v0.1b MTE"

    strings:
        $pattern = { E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? B9 1B 01 ?? ?? D1 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PESHiELD_v02___v02b___v02b2
{
    meta:
        description = "PESHiELD v0.2 / v0.2b / v0.2b2"

    strings:
        $pattern = { 60 E8 ?? ?? ?? ?? 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PESHiELD_v025
{
    meta:
        description = "PESHiELD v0.25"

    strings:
        $pattern = { 60 E8 2B 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PESHiELD_v0251
{
    meta:
        description = "PESHiELD v0.251"

    strings:
        $pattern = { 5D 83 ED 06 EB 02 EA 04 8D }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PEShit
{
    meta:
        description = "PEShit"

    strings:
        $pattern = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 83 F9 00 7E 06 80 30 ?? 40 E2 F5 E9 ?? ?? ?? FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Spin_v0b
{
    meta:
        description = "PE Spin v0.b"

    strings:
        $pattern = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 72 C8 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 26 E8 01 00 00 00 EA 5A 33 C9 8B 95 68 20 40 00 8B 42 3C 03 C2 89 85 76 20 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D 8A 20 40 00 8B 59 24 03 DA 8B 1B 89 9D 8E 20 40 00 53 8F 85 E2 1F 40 00 8D 85 92 20 40 00 6A 0C 5B 6A 17 59 30 0C 03 02 CB 4B 75 F8 40 8D 9D 41 8F 4E 00 50 53 81 2C 24 01 78 0E 00 FF B5 8A 20 40 00 C3 92 EB 15 68 BB ?? 00 00 00 B9 90 08 00 00 8D BD FF 20 40 00 4F 30 1C 39 FE CB E2 F9 68 1D 01 00 00 59 8D BD 2F 28 40 00 C0 0C 39 02 E2 FA 68 A0 20 40 00 50 01 6C 24 04 E8 BD 09 00 00 33 C0 0F 84 C0 08 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Spin_v03
{
    meta:
        description = "PE Spin v0.3"

    strings:
        $pattern = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 CB 2C 40 00 8B 42 3C 03 C2 89 85 D5 2C 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D E9 2C 40 00 53 8F 85 B6 2B 40 00 BB ?? 00 00 00 B9 75 0A 00 00 8D BD 7E 2D 40 00 4F 30 1C 39 FE CB E2 F9 68 3C 01 00 00 59 8D BD B6 36 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 1F 53 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D DC 2C 40 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Spin_v04x
{
    meta:
        description = "PE Spin v0.4x"

    strings:
        $pattern = { EB 01 68 60 E8 00 00 00 00 8B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PESpin_v11_by_cyberbob
{
    meta:
        description = "PESpin v1.1 by cyberbob"

    strings:
        $pattern = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 C3 4B 40 00 8B 42 3C 03 C2 89 85 CD 4B 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D E1 4B 40 00 53 8F 85 D7 49 40 00 BB ?? 00 00 00 B9 FE 11 00 00 8D BD 71 4C 40 00 4F EB 07 FA EB 01 FF EB 04 E3 EB F8 69 30 1C 39 FE CB 49 9C }
        $pattern_1 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 C3 4B 40 00 8B 42 3C 03 C2 89 85 CD 4B 40 00 EB 02 12 77 F9 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule PEtite_v12
{
    meta:
        description = "PEtite v1.2"

    strings:
        $pattern = { 9C 60 E8 CA ?? ?? ?? 03 ?? 04 ?? 05 ?? 06 ?? 07 ?? 08 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PEtite_v13
{
    meta:
        description = "PEtite v1.3"

    strings:
        $pattern = { ?? ?? ?? ?? ?? 66 9C 60 50 8D 88 ?? F0 ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1 68 ?? ?? ?? ?? 53 50 80 04 24 08 50 80 04 24 42 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PEtite_v14
{
    meta:
        description = "PEtite v1.4"

    strings:
        $pattern = { ?? ?? ?? ?? ?? 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC }
        $pattern_1 = { 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 14 8B CC }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule PEtite_v20
{
    meta:
        description = "PEtite v2.0"

    strings:
        $pattern = { B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 18 8B CC 8D A0 54 BC ?? ?? 8B C3 8D 90 E0 15 ?? ?? 68 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PEtite_v21
{
    meta:
        description = "PEtite v2.1"

    strings:
        $pattern = { B8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PEtite_v22
{
    meta:
        description = "PEtite v2.2"

    strings:
        $pattern = { B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PEtite_vxx
{
    meta:
        description = "PEtite vx.x"

    strings:
        $pattern = { B8 ?? ?? ?? ?? 66 9C 60 50 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PEX_v099
{
    meta:
        description = "PEX v0.99"

    strings:
        $pattern = { E9 F5 ?? ?? ?? 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }
        $pattern_1 = { 60 E8 01 ?? ?? ?? ?? 83 C4 04 E8 01 ?? ?? ?? ?? 5D 81 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule PKLITE32_v11
{
    meta:
        description = "PKLITE32 v1.1"

    strings:
        $pattern = { 55 8B EC A1 ?? ?? ?? ?? 85 C0 74 09 B8 01 ?? ?? ?? 5D C2 0C ?? 8B 45 0C 57 56 53 8B 5D 10 }
        $pattern_1 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 00 00 00 00 E8 }
        $pattern_2 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 4B 4C 49 54 45 33 32 20 43 6F 70 79 72 69 67 68 74 20 31 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Private_EXE_v20a
{
    meta:
        description = "Private EXE v2.0a"

    strings:
        $pattern = { 53 E8 ?? ?? ?? ?? 5B 8B C3 2D }
        $pattern_1 = { EB ?? CD ?? ?? ?? ?? ?? CD ?? ?? ?? ?? ?? EB ?? EB ?? EB ?? EB ?? CD ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 50 C3 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule PrincessSandy_v10_eMiNENCE_Process_Patcher_Patch
{
    meta:
        description = "PrincessSandy v1.0 eMiNENCE Process Patcher Patch"

    strings:
        $pattern = { 68 27 11 40 00 E8 3C 01 00 00 6A 00 E8 41 01 00 00 A3 00 20 40 00 8B 58 3C 03 D8 0F B7 43 14 0F B7 4B 06 8D 7C 18 18 81 3F 2E 4C 4F 41 74 0B 83 C7 28 49 75 F2 E9 A7 00 00 00 8B 5F 0C 03 1D 00 20 40 00 89 1D 04 20 40 00 8B FB 83 C7 04 68 4C 20 40 00 68 08 20 40 00 6A 00 6A 00 6A 20 6A 00 6A 00 6A 00 57 6A 00 E8 CE 00 00 00 85 C0 74 78 BD 50 C3 00 00 8B 3D 04 20 40 00 8B 07 8D 3C 07 83 C7 04 89 3D 04 20 40 00 8B 0F 83 C7 04 8B 1F 83 C7 04 4D 85 ED 74 57 60 6A 00 51 68 5C 20 40 00 53 FF 35 4C 20 40 00 E8 93 00 00 00 85 C0 61 74 E1 8B C1 60 BE 5C 20 40 00 F3 A6 74 03 61 EB D2 60 6A 00 50 57 53 FF 35 4C 20 40 00 E8 7A 00 00 00 85 C0 74 20 61 83 3C 07 00 74 2D 03 F8 EB A8 B8 5E 21 40 00 EB 13 B8 7C 21 40 00 EB 0C B8 9E 21 40 00 EB 05 B8 CF 21 40 00 6A 00 68 56 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Program_Protector_XP_v10
{
    meta:
        description = "Program Protector XP v1.0"

    strings:
        $pattern = { E8 ?? ?? ?? ?? 58 83 D8 05 89 C3 81 C3 ?? ?? ?? ?? 8B 43 64 50 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Protection_Plus_vxx
{
    meta:
        description = "Protection Plus vx.x"

    strings:
        $pattern = { 50 60 29 C0 64 FF 30 E8 ?? ?? ?? ?? 5D 83 ED 3C 89 E8 89 A5 14 ?? ?? ?? 2B 85 1C ?? ?? ?? 89 85 1C ?? ?? ?? 8D 85 27 03 ?? ?? 50 8B ?? 85 C0 0F 85 C0 ?? ?? ?? 8D BD 5B 03 ?? ?? 8D B5 43 03 ?? ?? E8 DD ?? ?? ?? 89 85 1F 03 ?? ?? 6A 40 68 ?? 10 ?? ?? 8B 85 28 ?? ?? ?? 50 6A }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule RatPacker_Glue_stub
{
    meta:
        description = "RatPacker (Glue) stub"

    strings:
        $pattern = { 40 20 FF ?? ?? ?? ?? ?? ?? ?? ?? BE ?? 60 40 ?? 8D BE ?? B0 FF FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule R1SCs_Process_Patcher_v14
{
    meta:
        description = "R!SC's Process Patcher v1.4"

    strings:
        $pattern = { E8 E1 01 00 00 80 38 22 75 13 80 38 00 74 2E 80 38 20 75 06 80 78 FF 22 74 18 40 EB ED 80 38 00 74 1B EB 19 40 80 78 FF 20 75 F9 80 38 00 74 0D EB 0B 40 80 38 00 74 05 80 38 22 74 00 8B F8 B8 04 60 40 00 68 00 20 40 00 C7 05 A2 20 40 00 44 00 00 00 68 92 20 40 00 68 A2 20 40 00 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 57 50 E8 7C 01 00 00 85 C0 0F 84 2A 01 00 00 B8 00 60 40 00 8B 00 A3 1C 22 40 00 BE 40 60 40 00 83 7E FC 00 0F 84 F6 00 00 00 8B 3E 83 C6 04 85 FF 0F 84 83 00 00 00 81 FF 72 21 73 63 0F 84 DD 00 00 00 33 DB 66 8B 1E 8B CF 8D 7E 02 C7 05 EA 21 40 00 00 00 00 00 83 05 EA 21 40 00 01 50 A1 1C 22 40 00 39 05 EA 21 40 00 58 0F 84 C1 00 00 00 60 6A 00 53 68 EA 20 40 00 51 FF 35 92 20 40 00 E8 EB 00 00 00 61 60 FC BE EA 20 40 00 8B CB F3 A6 61 75 C2 03 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule R1SCs_Process_Patcher_v151
{
    meta:
        description = "R!SC's Process Patcher v1.5.1"

    strings:
        $pattern = { 68 00 20 40 00 E8 C3 01 00 00 80 38 00 74 0D 66 81 78 FE 22 20 75 02 EB 03 40 EB EE 8B F8 B8 04 60 40 00 68 C4 20 40 00 68 D4 20 40 00 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 57 50 E8 9F 01 00 00 85 C0 0F 84 39 01 00 00 BE 00 60 40 00 8B 06 A3 28 21 40 00 83 C6 40 83 7E FC 00 0F 84 8F 00 00 00 8B 3E 83 C6 04 85 FF 0F 84 E5 00 00 00 81 FF 72 21 73 63 74 7A 0F B7 1E 8B CF 8D 7E 02 C7 05 24 21 40 00 00 00 00 00 83 05 24 21 40 00 01 50 A1 28 21 40 00 39 05 24 21 40 00 58 0F 84 D8 00 00 00 60 6A 00 53 68 2C 21 40 00 51 FF 35 C4 20 40 00 E8 0A 01 00 00 61 60 FC BE 2C 21 40 00 8B CB F3 A6 61 75 C2 03 FB 60 E8 3E 00 00 00 6A 00 53 57 51 FF 35 C4 20 40 00 E8 FB 00 00 00 85 C0 0F 84 A2 00 00 00 61 03 FB 8B F7 E9 71 FF FF FF 60 FF 35 C8 20 40 00 E8 CB 00 00 00 61 C7 05 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Shrinker_v32
{
    meta:
        description = "Shrinker v3.2"

    strings:
        $pattern = { 83 3D ?? ?? ?? ?? ?? 55 8B EC 56 57 75 65 68 00 01 ?? ?? E8 ?? E6 FF FF 83 C4 04 8B 75 08 A3 ?? ?? ?? ?? 85 F6 74 1D 68 FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Shrinker_v33
{
    meta:
        description = "Shrinker v3.3"

    strings:
        $pattern = { 83 3D ?? ?? ?? 00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Shrinker_v34
{
    meta:
        description = "Shrinker v3.4"

    strings:
        $pattern = { 83 3D B4 ?? ?? ?? ?? 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 ?? 0B 00 00 83 C4 04 8B 75 08 A3 B4 ?? ?? ?? 85 F6 74 23 83 7D 0C 03 77 1D 68 FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Shrink_Wrap_v14
{
    meta:
        description = "Shrink Wrap v1.4"

    strings:
        $pattern = { 58 60 8B E8 55 33 F6 68 48 01 ?? ?? E8 49 01 ?? ?? EB }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule SecuPack_v15
{
    meta:
        description = "SecuPack v1.5"

    strings:
        $pattern = { 55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 CC 3A 40 ?? E8 E0 FC FF FF 33 C0 55 68 EA 3C 40 ?? 64 FF 30 64 89 20 6A ?? 68 80 ?? ?? ?? 6A 03 6A ?? 6A 01 ?? ?? ?? 80 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule SmokesCrypt_v12
{
    meta:
        description = "SmokesCrypt v1.2"

    strings:
        $pattern = { 60 B8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Soft_Defender_v10___v11
{
    meta:
        description = "Soft Defender v1.0 - v1.1"

    strings:
        $pattern = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD ?? 59 9C 50 74 0A 75 08 E8 59 C2 04 ?? 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 ?? ?? ?? ?? 58 05 BA 01 ?? ?? 03 C8 74 BE 75 BC E8 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule SoftSentry_v211
{
    meta:
        description = "SoftSentry v2.11"

    strings:
        $pattern = { 55 8B EC 83 EC ?? 53 56 57 E9 50 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule SoftSentry_v30
{
    meta:
        description = "SoftSentry v3.0"

    strings:
        $pattern = { 55 8B EC 83 EC ?? 53 56 57 E9 B0 06 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule SoftWrap
{
    meta:
        description = "SoftWrap"

    strings:
        $pattern = { 52 53 51 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 36 ?? ?? ?? E8 ?? 01 ?? ?? 60 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Soft_Defender_v112
{
    meta:
        description = "Soft Defender v1.12"

    strings:
        $pattern = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD 00 59 9C 50 74 0A 75 08 E8 59 C2 04 00 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 BE 01 00 00 03 C8 74 BD 75 BB E8 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Spalsher_v10___v30
{
    meta:
        description = "Spalsher v1.0 - v3.0"

    strings:
        $pattern = { 9C 60 8B 44 24 24 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 50 E8 ED 02 ?? ?? 8C C0 0F 84 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Special_EXE_Password_Protector_v10
{
    meta:
        description = "Special EXE Password Protector v1.0"

    strings:
        $pattern = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E 77 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule SPEC_b2
{
    meta:
        description = "SPEC b2"

    strings:
        $pattern = { 55 57 51 53 E8 ?? ?? ?? ?? 5D 8B C5 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 09 89 85 ?? ?? ?? ?? 0F B6 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule SPEC_b3
{
    meta:
        description = "SPEC b3"

    strings:
        $pattern = { 5B 53 50 45 43 5D E8 ?? ?? ?? ?? 5D 8B C5 81 ED 41 24 40 ?? 2B 85 89 26 40 ?? 83 E8 0B 89 85 8D 26 40 ?? 0F B6 B5 91 26 40 ?? 8B FD }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule SPLayer_v008
{
    meta:
        description = "SPLayer v0.08"

    strings:
        $pattern = { 8D 40 00 B9 ?? ?? ?? ?? 6A ?? 58 C0 0C ?? ?? 48 ?? ?? 66 13 F0 91 3B D9 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Stealth_PE_v11
{
    meta:
        description = "Stealth PE v1.1"

    strings:
        $pattern = { BA ?? ?? ?? 00 FF E2 BA ?? ?? ?? 00 B8 ?? ?? ?? ?? 89 02 83 C2 03 B8 ?? ?? ?? ?? 89 02 83 C2 FD FF E2 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Stones_PE_Encryptor_v10
{
    meta:
        description = "Stone's PE Encryptor v1.0"

    strings:
        $pattern = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 63 3A 40 ?? 2B 95 C2 3A 40 ?? 83 EA 0B 89 95 CB 3A 40 ?? 8D B5 CA 3A 40 ?? 0F B6 36 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Stones_PE_Encryptor_v113
{
    meta:
        description = "Stone's PE Encryptor v1.13"

    strings:
        $pattern = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 97 3B 40 ?? 2B 95 2D 3C 40 ?? 83 EA 0B 89 95 36 3C 40 ?? 01 95 24 3C 40 ?? 01 95 28 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Stones_PE_Encryptor_v20
{
    meta:
        description = "Stone's PE Encryptor v2.0"

    strings:
        $pattern = { 53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 42 30 40 ?? FF 95 32 35 40 ?? B8 37 30 40 ?? 03 C5 2B 85 1B 34 40 ?? 89 85 27 34 40 ?? 83 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule SVK_Protector_v111
{
    meta:
        description = "SVK-Protector v1.11"

    strings:
        $pattern = { 60 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? 64 A0 23 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule SVK_Protector_v1051
{
    meta:
        description = "SVK-Protector v1.051"

    strings:
        $pattern = { 60 EB 03 C7 84 E8 EB 03 C7 84 9A E8 00 00 00 00 5D 81 ED 10 00 00 00 EB 03 C7 84 E9 64 A0 23 00 00 00 EB }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule SVK_Protector_v132
{
    meta:
        description = "SVK-Protector v1.32"

    strings:
        $pattern = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 06 36 42 00 64 A0 23 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Symantec_Visual_Cafe_v30
{
    meta:
        description = "Symantec Visual Cafe v3.0"

    strings:
        $pattern = { 64 8B 05 ?? ?? ?? ?? 55 8B EC 6A FF 68 ?? ?? 40 ?? 68 ?? ?? 40 ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 08 50 53 56 57 89 65 E8 C7 45 FC }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Silicon_Realms_Install_Stub
{
    meta:
        description = "Silicon Realms Install Stub"

    strings:
        $pattern = { 55 8B EC 6A FF 68 ?? 92 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 ?? ?? 40 00 33 D2 8A D4 89 15 ?? ?? 40 00 8B C8 81 E1 FF 00 00 00 89 0D ?? ?? 40 00 C1 E1 08 03 CA 89 0D ?? ?? 40 00 C1 E8 10 A3 ?? ?? 40 00 33 F6 56 E8 ?? ?? 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 ?? ?? 00 00 FF 15 ?? 91 40 00 A3 ?? ?? 40 00 E8 ?? ?? 00 00 A3 ?? ?? 40 00 E8 ?? ?? 00 00 E8 ?? ?? 00 00 E8 ?? ?? FF FF 89 75 D0 8D 45 A4 50 FF 15 ?? 91 40 00 E8 ?? ?? 00 00 89 45 9C F6 45 D0 01 74 06 0F B7 45 D4 EB 03 6A 0A 58 50 FF 75 9C 56 56 FF 15 ?? 91 40 00 50 E8 ?? ?? FF FF 89 45 A0 50 E8 ?? ?? FF FF 8B 45 EC 8B 08 8B 09 89 4D 98 50 51 E8 ?? ?? 00 00 59 59 C3 8B 65 E8 FF 75 98 E8 ?? ?? FF FF 83 3D ?? ?? 40 00 01 75 05 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule SOFTWrapper_for_Win9x_NT_Evaluation_Version
{
    meta:
        description = "SOFTWrapper for Win9x/NT (Evaluation Version)"

    strings:
        $pattern = { E8 00 00 00 00 5D 8B C5 2D ?? ?? ?? 00 50 81 ED 05 00 00 00 8B C5 2B 85 03 0F 00 00 89 85 03 0F 00 00 8B F0 03 B5 0B 0F 00 00 8B F8 03 BD 07 0F 00 00 83 7F 0C 00 74 2B 56 57 8B 7F 10 03 F8 8B 76 10 03 F0 83 3F 00 74 0C 8B 1E 89 1F 83 C6 04 83 C7 04 EB EF 5F 5E 83 C6 14 83 C7 14 EB D3 00 00 00 00 8B F5 81 C6 0D 0A 00 00 B9 0C 00 00 00 8B 85 03 0F 00 00 01 46 02 83 C6 06 E2 F8 E8 06 08 00 00 68 00 01 00 00 8D 85 DD 0D 00 00 50 6A 00 E8 95 09 00 00 8B B5 03 0F 00 00 66 81 3E 4D 5A 75 33 03 76 3C 81 3E 50 45 00 00 75 28 8B 46 28 03 85 03 0F 00 00 3B C5 74 1B 6A 30 E8 99 09 00 00 6A 30 8D 85 DD 0D 00 00 50 8D 85 2B 0F 00 00 E9 55 03 00 00 66 8B 85 9D 0A 00 00 F6 C4 80 74 31 E8 6A 07 00 00 0B C0 75 23 6A 40 E8 69 09 00 00 6A 40 8D 85 DD 0D 00 00 50 8B 9D 17 0F }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v100
{
    meta:
        description = "tElock v1.00"

    strings:
        $pattern = { E9 E5 E2 FF FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v041x
{
    meta:
        description = "tElock v0.41x"

    strings:
        $pattern = { 66 8B C0 8D 24 24 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 50 8B FE 68 78 01 ?? ?? 59 EB 01 EB AC 54 E8 03 ?? ?? ?? 5C EB 08 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v042
{
    meta:
        description = "tElock v0.42"

    strings:
        $pattern = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 52 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v051
{
    meta:
        description = "tElock v0.51"

    strings:
        $pattern = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 5E 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v04x___v05x
{
    meta:
        description = "tElock v0.4x - v0.5x"

    strings:
        $pattern = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 ?? 8B FE 68 79 01 ?? ?? 59 EB 01 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v060
{
    meta:
        description = "tElock v0.60"

    strings:
        $pattern = { E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0 08 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v070
{
    meta:
        description = "tElock v0.70"

    strings:
        $pattern = { 60 E8 BD 10 00 00 C3 83 E2 00 F9 75 FA 70 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v071
{
    meta:
        description = "tElock v0.71"

    strings:
        $pattern = { 60 E8 ED 10 00 00 C3 83 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v071b2
{
    meta:
        description = "tElock v0.71b2"

    strings:
        $pattern = { 60 E8 44 11 00 00 C3 83 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v071b7
{
    meta:
        description = "tElock v0.71b7"

    strings:
        $pattern = { 60 E8 48 11 00 00 C3 83 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v080
{
    meta:
        description = "tElock v0.80"

    strings:
        $pattern = { 60 E8 F9 11 00 00 C3 83 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v07x___v084
{
    meta:
        description = "tElock v0.7x - v0.84"

    strings:
        $pattern = { 60 E8 00 00 C3 83 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v085f
{
    meta:
        description = "tElock v0.85f"

    strings:
        $pattern = { 60 E8 02 00 00 00 CD 20 E8 00 00 00 00 5E 2B C9 58 74 02 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v090
{
    meta:
        description = "tElock v0.90"

    strings:
        $pattern = { ?? ?? E8 02 00 00 00 E8 00 E8 00 00 00 00 5E 2B }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v092a
{
    meta:
        description = "tElock v0.92a"

    strings:
        $pattern = { E9 7E E9 FF FF 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v095
{
    meta:
        description = "tElock v0.95"

    strings:
        $pattern = { E9 D5 E4 FF FF 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v096
{
    meta:
        description = "tElock v0.96"

    strings:
        $pattern = { E9 59 E4 FF FF 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v098
{
    meta:
        description = "tElock v0.98"

    strings:
        $pattern = { E9 25 E4 FF FF 00 00 00 ?? ?? ?? ?? 1E }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v098b1
{
    meta:
        description = "tElock v0.98b1"

    strings:
        $pattern = { E9 25 E4 FF FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v098b2
{
    meta:
        description = "tElock v0.98b2"

    strings:
        $pattern = { E9 1B E4 FF FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule tElock_v099
{
    meta:
        description = "tElock v0.99"

    strings:
        $pattern = { E9 ?? ?? FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? 02 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 ?? ?? 02 00 00 00 00 00 ?? ?? 02 00 00 00 00 00 ?? ?? 02 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? 02 00 ?? ?? 02 00 ?? ?? 02 00 ?? ?? 02 00 77 ?? 02 00 ?? ?? 02 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? 00 00 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 00 00 ?? 00 00 ?? ?? 00 ?? ?? 00 00 ?? ?? ?? 00 00 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule The_Guard_Library
{
    meta:
        description = "The Guard Library"

    strings:
        $pattern = { 50 E8 ?? ?? ?? ?? 58 25 ?? F0 FF FF 8B C8 83 C1 60 51 83 C0 40 83 EA 06 52 FF 20 9D C3 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Thinstall_vxx
{
    meta:
        description = "Thinstall vx.x"

    strings:
        $pattern = { B8 EF BE AD DE 50 6A ?? FF 15 10 19 40 ?? E9 AD FF FF FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Trainer_Creation_Kit_v5_Trainer
{
    meta:
        description = "Trainer Creation Kit v5 Trainer"

    strings:
        $pattern = { 6A 00 68 80 00 00 00 6A 02 6A 00 6A 00 68 00 00 00 40 68 25 45 40 00 E8 3C 02 00 00 50 6A 00 68 40 45 40 00 68 00 10 00 00 68 00 30 40 00 50 E8 54 02 00 00 58 50 E8 17 02 00 00 6A 00 E8 2E 02 00 00 A3 70 45 40 00 68 25 45 40 00 E8 2B 02 00 00 A3 30 45 40 00 68 34 45 40 00 50 E8 15 02 00 00 6A 00 FF 35 30 45 40 00 50 6A 02 E8 4D 02 00 00 A3 74 45 40 00 6A 00 68 D4 10 40 00 6A 00 6A 01 FF 35 70 45 40 00 E8 02 02 00 00 B3 0A FE CB 74 10 FF 35 74 45 40 00 E8 27 02 00 00 83 F8 00 74 EC B3 0A FE CB 74 10 FF 35 30 45 40 00 E8 B7 01 00 00 83 F8 00 74 EC B3 0A FE CB 74 16 68 25 45 40 00 E8 96 01 00 00 83 F8 00 74 ED 6A 00 E8 90 01 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 0F 85 C7 00 00 00 6A 01 FF 35 70 45 40 00 E8 B0 01 00 00 50 6A 01 68 80 00 00 00 FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UG2002_Cruncher_v03b3
{
    meta:
        description = "UG2002 Cruncher v0.3b3"

    strings:
        $pattern = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? E8 0D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPack_v011
{
    meta:
        description = "UPack v0.11"

    strings:
        $pattern = { BE 48 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 1C F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 03 B3 00 8D 1C 5B 8D 9C 9E 0C 10 00 00 B0 01 67 E3 29 8B D7 2B 56 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF D5 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E4 B4 00 33 C9 B5 01 FF 55 CC 33 C9 E9 DF 00 00 00 8B 5E 0C 83 C2 30 FF D5 73 50 83 C2 30 FF D5 72 1B 83 C2 30 FF D5 72 2B 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 46 0C B1 80 8A 00 EB CF 83 C2 60 FF D5 87 5E 10 73 0D 83 C2 30 FF D5 87 5E 14 73 03 87 5E 18 3C 07 B0 08 72 02 B0 0B 50 53 8D 96 7C 07 00 00 FF 55 D0 5B 91 EB 77 3C 07 B0 07 72 02 B0 0A 50 87 5E 10 87 5E 14 89 5E 18 8D 96 C4 0B 00 00 FF 55 D0 50 48 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_v051
{
    meta:
        description = "UPX v0.51"

    strings:
        $pattern = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 8D B0 D8 01 ?? ?? 83 CD FF 31 DB ?? ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 0B 8A 06 46 88 07 47 EB EB 90 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_v060___v061
{
    meta:
        description = "UPX v0.60 - v0.61"

    strings:
        $pattern = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 8D B0 E8 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_v062
{
    meta:
        description = "UPX v0.62"

    strings:
        $pattern = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 F0 01 ?? ?? 83 CD FF 31 DB 90 90 90 EB 08 90 90 8A 06 46 88 07 47 01 DB 75 07 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_v070
{
    meta:
        description = "UPX v0.70"

    strings:
        $pattern = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 EC 01 ?? ?? 83 CD FF 31 DB EB 07 90 8A 06 46 88 07 47 01 DB 75 07 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_v071___v072
{
    meta:
        description = "UPX v0.71 - v0.72"

    strings:
        $pattern = { 60 E8 00 00 00 00 83 CD FF 31 DB 5E 8D BE FA ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 81 C6 B3 01 ?? ?? EB 0A ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_v0896___v102___v105___v122_DLL
{
    meta:
        description = "UPX v0.89.6 - v1.02 / v1.05 - v1.22 DLL"

    strings:
        $pattern = { 80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
        $pattern_1 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule UPX_v080___v084
{
    meta:
        description = "UPX v0.80 - v0.84"

    strings:
        $pattern = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF 75 09 8B 1E 83 EE FC }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_v103___v104
{
    meta:
        description = "UPX v1.03 - v1.04"

    strings:
        $pattern = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_v0896___v102___v105__v122_Delphi_stub
{
    meta:
        description = "UPX v0.89.6 - v1.02 / v1.05 -v1.22 (Delphi) stub"

    strings:
        $pattern = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF EB 0E ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_v081___v084_Modified
{
    meta:
        description = "UPX v0.81 - v0.84 Modified"

    strings:
        $pattern = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_v0896___v102___v105___v122_Modified
{
    meta:
        description = "UPX v0.89.6 - v1.02 / v1.05 - v1.22 Modified"

    strings:
        $pattern = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_v103___v104_Modified
{
    meta:
        description = "UPX v1.03 - v1.04 Modified"

    strings:
        $pattern = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB 8A 07 ?? EB B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_Alternative_stub
{
    meta:
        description = "UPX Alternative stub"

    strings:
        $pattern = { 01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 00 00 00 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_Modifier_v01x
{
    meta:
        description = "UPX Modifier v0.1x"

    strings:
        $pattern = { 50 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_Modified_stub
{
    meta:
        description = "UPX Modified stub"

    strings:
        $pattern = { 79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 84 ?? 00 00 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 88 ?? 00 00 61 E9 ?? ?? ?? FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_Protector_v10x_1
{
    meta:
        description = "UPX Protector v1.0x (1)"

    strings:
        $pattern = { EB EC ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_Protector_v10x_2
{
    meta:
        description = "UPX Protector v1.0x (2)"

    strings:
        $pattern = { EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_p_ECLiPSE_layer
{
    meta:
        description = "UPX + ECLiPSE layer"

    strings:
        $pattern = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 33 D2 EB 01 0F 56 EB 01 0F E8 03 00 00 00 EB 01 0F EB 01 0F 5E EB 01 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_Scrambler_RC_v1x
{
    meta:
        description = "UPX-Scrambler RC v1.x"

    strings:
        $pattern = { 90 61 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPXShit_006
{
    meta:
        description = "UPXShit 0.06"

    strings:
        $pattern = { B8 ?? ?? 43 00 B9 15 00 00 00 80 34 08 ?? E2 FA E9 D6 FF FF FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_HiT_v001
{
    meta:
        description = "UPX$HiT v0.0.1"

    strings:
        $pattern = { 94 BC ?? ?? ?? 00 B9 ?? 00 00 00 80 34 0C ?? E2 FA 94 FF E0 61 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_Inliner_v10_by_GPcH
{
    meta:
        description = "UPX Inliner v1.0 by GPcH"

    strings:
        $pattern = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D5 FE FF FF 8B 06 83 F8 00 74 11 8D B5 E1 FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 B1 FE FF FF 2B D0 89 95 B1 FE FF FF 01 95 C9 FE FF FF 8D B5 E5 FE FF FF 01 16 8B 36 8B FD 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 05 FF FF FF 85 C0 0F 84 06 03 00 00 89 85 C5 FE FF FF E8 00 00 00 00 5B B9 31 89 40 00 81 E9 2E 86 40 00 03 D9 50 53 E8 3D 02 00 00 61 03 BD A9 FE FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 2D 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 09 FF FF FF FF B5 05 FF FF FF 56 57 FF 95 C5 FE FF FF 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB CE 68 00 80 00 00 6A 00 FF B5 C5 FE FF FF FF 95 09 FF FF FF 8D }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule VBOX_v42_MTE
{
    meta:
        description = "VBOX v4.2 MTE"

    strings:
        $pattern = { 8C E0 0B C5 8C E0 0B C4 03 C5 74 00 74 00 8B C5 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule VBOX_v43_MTE
{
    meta:
        description = "VBOX v4.3 MTE"

    strings:
        $pattern = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule VOB_ProtectCD_5
{
    meta:
        description = "VOB ProtectCD 5"

    strings:
        $pattern = { 36 3E 26 8A C0 60 E8 }
        $pattern_1 = { 5F 81 EF ?? ?? ?? ?? BE ?? ?? 40 ?? 8B 87 ?? ?? ?? ?? 03 C6 57 56 8C A7 ?? ?? ?? ?? FF 10 89 87 ?? ?? ?? ?? 5E 5F }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Virogen_Crypt_v075
{
    meta:
        description = "Virogen Crypt v0.75"

    strings:
        $pattern = { 9C 55 E8 EC 00 00 00 87 D5 5D 60 87 D5 80 BD 15 27 40 00 01 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule VIRUS___I_WormBagle
{
    meta:
        description = "VIRUS - I-Worm.Bagle"

    strings:
        $pattern = { 6A 00 E8 95 01 00 00 E8 9F E6 FF FF 83 3D 03 50 40 00 00 75 14 68 C8 AF 00 00 E8 01 E1 FF FF 05 88 13 00 00 A3 03 50 40 00 68 5C 57 40 00 68 F6 30 40 00 FF 35 03 50 40 00 E8 B0 EA FF FF E8 3A FC FF FF 83 3D 54 57 40 00 00 74 05 E8 F3 FA FF FF 68 E8 03 00 00 E8 B1 00 00 00 EB F4 CC FF 25 A4 40 40 00 FF 25 B8 40 40 00 FF 25 B4 40 40 00 FF 25 B0 40 40 00 FF 25 AC 40 40 00 FF 25 9C 40 40 00 FF 25 A0 40 40 00 FF 25 A8 40 40 00 FF 25 24 40 40 00 FF 25 28 40 40 00 FF 25 2C 40 40 00 FF 25 30 40 40 00 FF 25 34 40 40 00 FF 25 38 40 40 00 FF 25 3C 40 40 00 FF 25 40 40 40 00 FF 25 44 40 40 00 FF 25 48 40 40 00 FF 25 4C 40 40 00 FF 25 50 40 40 00 FF 25 54 40 40 00 FF 25 58 40 40 00 FF 25 5C 40 40 00 FF 25 60 40 40 00 FF 25 BC 40 40 00 FF 25 64 40 40 00 FF 25 68 40 40 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule VIRUS___I_WormKLEZ
{
    meta:
        description = "VIRUS - I-Worm.KLEZ"

    strings:
        $pattern = { 55 8B EC 6A FF 68 40 D2 40 ?? 68 04 AC 40 ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 BC D0 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule VIRUS___I_WormHybris
{
    meta:
        description = "VIRUS - I-Worm.Hybris"

    strings:
        $pattern = { EB 16 A8 54 ?? ?? 47 41 42 4C 4B 43 47 43 ?? ?? ?? ?? ?? ?? 52 49 53 ?? FC 68 4C 70 40 ?? FF 15 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Winkript_v10
{
    meta:
        description = "Winkript v1.0"

    strings:
        $pattern = { 33 C0 8B B8 00 ?? ?? ?? 8B 90 04 ?? ?? ?? 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0 58 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule WinZip_32_bit_SFX_v6x_module
{
    meta:
        description = "WinZip 32-bit SFX v6.x module"

    strings:
        $pattern = { FF 15 ?? ?? ?? 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10 38 08 74 06 40 80 38 00 75 F6 80 38 00 74 01 40 33 C9 ?? ?? ?? ?? FF 15 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule WinZip_32_bit_SFX_v8x_module
{
    meta:
        description = "WinZip 32-bit SFX v8.x module"

    strings:
        $pattern = { 53 FF 15 ?? ?? ?? 00 B3 22 38 18 74 03 80 C3 FE 8A 48 01 40 33 D2 3A CA 74 0A 3A CB 74 06 8A 48 01 40 EB F2 38 10 74 01 40 ?? ?? ?? ?? FF 15 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule WinRAR_32_bit_SFX_Module
{
    meta:
        description = "WinRAR 32-bit SFX Module"

    strings:
        $pattern = { E9 ?? ?? 00 00 00 00 00 00 90 90 90 ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Wise_Installer_Stub
{
    meta:
        description = "Wise Installer Stub"

    strings:
        $pattern = { 55 8B EC 81 EC ?? 04 00 00 53 56 57 6A ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? 40 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 ?? 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 74 }
        $pattern_1 = { 55 8B EC 81 EC 78 05 00 00 53 56 BE 04 01 00 00 57 8D 85 94 FD FF FF 56 33 DB 50 53 FF 15 34 20 40 00 8D 85 94 FD FF FF 56 50 8D 85 94 FD FF FF 50 FF 15 30 20 40 00 8B 3D 2C 20 40 00 53 53 6A 03 53 6A 01 8D 85 94 FD FF FF 68 00 00 00 80 50 FF D7 83 F8 FF 89 45 FC 0F 84 7B 01 00 00 8D 85 90 FC FF FF 50 56 FF 15 28 20 40 00 8D 85 98 FE FF FF 50 53 8D 85 90 FC FF FF 68 10 30 40 00 50 FF 15 24 20 40 00 53 68 80 00 00 00 6A 02 53 53 8D 85 98 FE FF FF 68 00 00 00 40 50 FF D7 83 F8 FF 89 45 F4 0F 84 2F 01 00 00 53 53 53 6A 02 53 FF 75 FC FF 15 00 20 40 00 53 53 53 6A 04 50 89 45 F8 FF 15 1C 20 40 00 8B F8 C7 45 FC 01 00 00 00 8D 47 01 8B 08 81 F9 4D 5A 9A 00 74 08 81 F9 4D 5A 90 00 75 06 80 78 04 03 74 0D FF 45 FC 40 81 7D FC 00 80 00 00 7C DB 8D 4D F0 53 51 68 }
        $pattern_2 = { 55 8B EC 81 EC ?? ?? 00 00 53 56 57 6A 01 5E 6A 04 89 75 E8 FF 15 ?? 40 40 00 FF 15 ?? 40 40 00 8B F8 89 7D ?? 8A 07 3C 22 0F 85 ?? 00 00 00 8A 47 01 47 89 7D ?? 33 DB 3A C3 74 0D 3C 22 74 09 8A 47 01 47 89 7D ?? EB EF 80 3F 22 75 04 47 89 7D ?? 80 3F 20 75 09 47 80 3F 20 74 FA 89 7D ?? 53 FF 15 ?? 40 40 00 80 3F 2F 89 45 ?? 75 ?? 8A 47 01 3C 53 74 04 3C 73 75 06 89 35 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Wise_Installer_Stub_v11010291
{
    meta:
        description = "Wise Installer Stub v1.10.1029.1"

    strings:
        $pattern = { 55 8B EC 81 EC 40 0F 00 00 53 56 57 6A 04 FF 15 F4 30 40 00 FF 15 74 30 40 00 8A 08 89 45 E8 80 F9 22 75 48 8A 48 01 40 89 45 E8 33 F6 84 C9 74 0E 80 F9 22 74 09 8A 48 01 40 89 45 E8 EB EE 80 38 22 75 04 40 89 45 E8 80 38 20 75 09 40 80 38 20 74 FA 89 45 E8 8A 08 80 F9 2F 74 2B 84 C9 74 1F 80 F9 3D 74 1A 8A 48 01 40 EB F1 33 F6 84 C9 74 D6 80 F9 20 74 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule WWPack32_v100_v111_v112_v120
{
    meta:
        description = "WWPack32 v1.00, v1.11, v1.12, v1.20"

    strings:
        $pattern = { 53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33 32 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule WWPack32_v1x
{
    meta:
        description = "WWPack32 v1.x"

    strings:
        $pattern = { 53 55 8B E8 33 DB EB 60 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule X_PEOR_v099b
{
    meta:
        description = "X-PEOR v0.99b"

    strings:
        $pattern = { E8 00 00 00 00 5D 8B CD 81 ED 7A 29 40 00 89 AD 0F 6D 40 00 }
        $pattern_1 = { E8 ?? ?? ?? ?? 5D 8B CD 81 ED 7A 29 40 ?? 89 AD 0F 6D 40 }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule Xtreme_Protector_v105
{
    meta:
        description = "Xtreme-Protector v1.05"

    strings:
        $pattern = { E9 ?? ?? 00 00 00 00 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Xtreme_Protector_v106
{
    meta:
        description = "Xtreme-Protector v1.06"

    strings:
        $pattern = { B8 ?? ?? ?? 00 B9 75 ?? ?? 00 50 51 E8 05 00 00 00 E9 4A 01 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 8A 06 46 88 07 47 BB 02 00 00 00 02 D2 75 05 8A 16 46 12 D2 73 EA 02 D2 75 05 8A 16 46 12 D2 73 4F 33 C0 02 D2 75 05 8A 16 46 12 D2 0F 83 DF 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 13 C0 74 06 57 2B F8 8A 07 5F 88 07 47 BB 02 00 00 00 EB 9B B8 01 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 72 EA 2B C3 BB 01 00 00 00 75 28 B9 01 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C9 02 D2 75 05 8A 16 46 12 D2 72 EA 56 8B F7 2B F5 F3 A4 5E E9 4F FF FF FF 48 C1 E0 08 8A 06 46 8B E8 B9 01 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C9 02 D2 75 05 8A 16 46 12 D2 72 EA 3D 00 7D 00 00 73 1A 3D 00 05 00 00 72 0E 41 56 8B F7 2B F0 F3 A4 5E E9 0F FF FF FF 83 F8 7F 77 03 83 C1 02 56 8B F7 2B F0 F3 A4 5E E9 FA FE FF FF 8A 06 46 33 C9 C0 E8 01 74 17 83 D1 02 8B E8 56 8B F7 2B F0 F3 A4 5E BB 01 00 00 00 E9 D9 FE FF FF 2B 7C 24 28 89 7C 24 1C 61 C2 08 00 E9 ?? ?? ?? 00 E9 38 ?? ?? ?? 01 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule XCR_v011
{
    meta:
        description = "XCR v0.11"

    strings:
        $pattern = { 60 8B F0 33 DB 83 C3 01 83 C0 01 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule XCR_v012
{
    meta:
        description = "XCR v0.12"

    strings:
        $pattern = { 60 9C E8 ?? ?? ?? ?? 8B DD 5D 81 ED ?? ?? ?? ?? 89 9D }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule XCR_v013
{
    meta:
        description = "XCR v0.13"

    strings:
        $pattern = { 93 71 08 ?? ?? ?? ?? ?? ?? ?? ?? 8B D8 78 E2 ?? ?? ?? ?? 9C 33 C3 ?? ?? ?? ?? 60 79 CE ?? ?? ?? ?? E8 01 ?? ?? ?? ?? 83 C4 04 E8 AB FF FF FF ?? ?? ?? ?? 2B E8 ?? ?? ?? ?? 03 C5 FF 30 ?? ?? ?? ?? C6 ?? EB }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule yP_v10b_by_Ashkbiz_Danehkar
{
    meta:
        description = "yP v1.0b by Ashkbiz Danehkar"

    strings:
        $pattern = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 C2 E8 03 00 00 00 EB 01 ?? AC ?? ?? ?? ?? ?? ?? ?? EB 01 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 01 E8 ?? AA E2 9C }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule y0das_Crypter_v10
{
    meta:
        description = "y0da's Crypter v1.0"

    strings:
        $pattern = { 60 E8 00 00 00 00 5D 81 ED E7 1A 40 00 E8 A1 00 00 00 E8 D1 00 00 00 E8 85 01 00 00 F7 85 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule y0das_Crypter_v11
{
    meta:
        description = "y0da's Crypter v1.1"

    strings:
        $pattern = { 60 E8 00 00 00 00 5D 81 ED 8A 1C 40 00 B9 9E 00 00 00 8D BD 4C 23 40 00 8B F7 33 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule y0das_Crypter_v12
{
    meta:
        description = "y0da's Crypter v1.2"

    strings:
        $pattern = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule y0das_Crypter_v1x___Modified
{
    meta:
        description = "y0da's Crypter v1.x / Modified"

    strings:
        $pattern = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 ?? ?? 00 00 8D BD ?? ?? ?? ?? 8B F7 AC }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule yC_v13_by_Ashkbiz_Danehkar
{
    meta:
        description = "yC v1.3 by Ashkbiz Danehkar"

    strings:
        $pattern = { 55 8B EC 81 EC C0 00 00 00 53 56 57 8D BD 40 FF FF FF B9 30 00 00 00 B8 CC CC CC CC F3 AB 60 E8 00 00 00 00 5D 81 ED 84 52 41 00 B9 75 5E 41 00 81 E9 DE 52 41 00 8B D5 81 C2 DE 52 41 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule ZCode_Win32_PE_Protector_v101
{
    meta:
        description = "ZCode Win32/PE Protector v1.01"

    strings:
        $pattern = { E9 12 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E9 FB FF FF FF C3 68 ?? ?? ?? ?? 64 FF 35 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule _Protector_v1111_DDeM_PE_Engine_v09_DDeM_CI_v092
{
    meta:
        description = "*** Protector v1.1.11 (DDeM->PE Engine v0.9, DDeM->CI v0.9.2)"

    strings:
        $pattern = { 53 51 56 E8 00 00 00 00 5B 81 EB 08 10 00 00 8D B3 34 10 00 00 B9 F3 03 00 00 BA 63 17 2A EE 31 16 83 C6 04 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule flat_assembler_v15x
{
    meta:
        description = "flat assembler v1.5x"

    strings:
        $pattern = { 6A 00 FF 15 ?? ?? 40 00 A3 ?? ?? 40 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Dev_Cpp_40
{
    meta:
        description = "Dev-C++ 4.0"

    strings:
        $pattern = { 55 89 E5 83 EC 08 83 C4 F4 6A ?? A1 ?? ?? ?? 00 FF D0 E8 ?? FF FF FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Inno_Setup_Module_Heuristic_Mode
{
    meta:
        description = "Inno Setup Module Heuristic Mode"

    strings:
        $pattern = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 ?? 89 45 ?? E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? FF FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Nullsoft_PiMP_Stub
{
    meta:
        description = "Nullsoft PiMP Stub"

    strings:
        $pattern = { 83 EC ?? 53 55 56 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Nullsoft_PiMP_Stub_v1x
{
    meta:
        description = "Nullsoft PiMP Stub v1.x"

    strings:
        $pattern = { 83 EC 0C 53 56 57 FF 15 ?? ?? 40 00 05 E8 03 00 00 BE ?? ?? ?? 00 89 44 24 10 B3 20 FF 15 28 ?? 40 00 68 00 04 00 00 FF 15 ?? ?? 40 00 50 56 FF 15 ?? ?? 40 00 80 3D ?? ?? ?? 00 22 75 08 80 C3 02 BE ?? ?? ?? 00 8A 06 8B 3D ?? ?? 40 00 84 C0 74 ?? 3A C3 74 0B 56 FF D7 8B F0 8A 06 84 C0 75 F1 80 3E 00 74 05 56 FF D7 8B F0 89 74 24 14 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 3E 2F }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule yodas_Crypter_v13
{
    meta:
        description = "yoda's Crypter v1.3"

    strings:
        $pattern = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 8C 21 40 00 B9 51 2D 40 00 81 E9 E6 21 40 00 8B D5 81 C2 E6 21 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule yodas_Protector_v1032
{
    meta:
        description = "yoda's Protector v1.03.2"

    strings:
        $pattern = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 94 73 42 00 8B D5 81 C2 E3 73 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule SoftDefender_v112_Unregistered
{
    meta:
        description = "SoftDefender v1.12 (Unregistered)"

    strings:
        $pattern = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD 00 59 9C 50 74 0A 75 08 E8 59 C2 04 00 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 E6 01 00 00 03 C8 74 BD 75 BB E8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule MASM32
{
    meta:
        description = "MASM32"

    strings:
        $pattern = { 6A ?? 68 00 30 40 00 68 ?? 30 40 00 6A 00 E8 07 00 00 00 6A 00 E8 06 00 00 00 FF 25 08 20 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v2xx
{
    meta:
        description = "PECompact v2.xx"

    strings:
        $pattern = { B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule eXPressor_v120b
{
    meta:
        description = "eXPressor v1.2.0b"

    strings:
        $pattern = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 ?? ?? ?? 00 2B 05 84 ?? ?? 00 A3 ?? ?? ?? 00 83 3D ?? ?? ?? 00 00 74 16 A1 ?? ?? ?? 00 03 05 80 ?? ?? 00 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 ?? ?? ?? 00 01 00 00 00 68 04 01 00 00 8D 85 F0 FE FF FF 50 6A 00 FF 15 ?? ?? ?? 00 8D 84 05 EF FE FF FF 89 85 38 FE FF FF 8B 85 38 FE FF FF 0F BE 00 83 F8 5C }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule UPX_v125_Delphi_Stub
{
    meta:
        description = "UPX v1.25 (Delphi) Stub"

    strings:
        $pattern = { 60 BE 00 ?? ?? 00 8D BE 00 ?? ?? FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Dev_Cpp_v499
{
    meta:
        description = "Dev-C++ v4.9.9"

    strings:
        $pattern = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 ?? ?? ?? 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 ?? ?? ?? 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D ?? ?? ?? 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D ?? ?? ?? 00 89 E5 5D FF E1 90 90 90 90 55 89 E5 5D E9 ?? ?? 00 00 90 90 90 90 90 90 90 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v25_Retail
{
    meta:
        description = "PECompact v2.5 Retail"

    strings:
        $pattern = { B8 ?? ?? ?? 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PECompact_v25_Retail_Slim_Loader
{
    meta:
        description = "PECompact v2.5 Retail (Slim Loader)"

    strings:
        $pattern = { B8 ?? ?? ?? 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule yodas_Protector_10_beta
{
    meta:
        description = "yoda's Protector 1.0 beta"

    strings:
        $pattern = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 ?? E8 03 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule InstallAnywhere_61
{
    meta:
        description = "InstallAnywhere 6.1"

    strings:
        $pattern = { 60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Upack_022___023_beta
{
    meta:
        description = "Upack 0.22 - 0.23 beta"

    strings:
        $pattern = { ?? ?? ?? ?? ?? ?? ?? AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 ?? 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule MingWin32_GCC_3x
{
    meta:
        description = "MingWin32 GCC 3.x"

    strings:
        $pattern = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? 40 00 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule REALbasic
{
    meta:
        description = "REALbasic"

    strings:
        $pattern = { 55 89 E5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PowerBASIC_CC_30x
{
    meta:
        description = "PowerBASIC/CC 3.0x"

    strings:
        $pattern = { 55 8B EC 53 56 57 BB 00 ?? ?? 00 66 2E F7 05 ?? ?? ?? 00 04 00 0F 85 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PowerBASIC_Win_70x
{
    meta:
        description = "PowerBASIC/Win 7.0x"

    strings:
        $pattern = { 55 8B EC 53 56 57 BB 00 ?? 40 00 66 2E F7 05 ?? ?? 40 00 04 00 0F 85 DB 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PE_Ninja_v10
{
    meta:
        description = "PE Ninja v1.0"

    strings:
        $pattern = { BE 5B 2A 40 00 BF 35 12 00 00 E8 40 12 00 00 3D 22 83 A3 C6 0F 85 67 0F 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Microsoft_Visual_Cpp_60_DLL
{
    meta:
        description = "Microsoft Visual C++ 6.0 DLL"

    strings:
        $pattern = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 75 09 83 3D ?? ?? ?? ?? ?? EB 26 83 FE 01 74 05 83 FE 02 75 22 A1 ?? ?? ?? ?? 85 C0 74 09 57 56 53 FF D0 85 C0 74 0C 57 56 53 E8 15 FF FF FF 85 C0 75 04 33 C0 EB 4E }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Watcom_C_Cpp
{
    meta:
        description = "Watcom C/C++"

    strings:
        $pattern = { E9 ?? ?? 00 00 03 10 40 00 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 69 6D 65 20 73 79 73 74 65 6D 2E 20 28 63 29 20 43 6F 70 79 72 69 67 68 74 20 62 79 20 57 41 54 43 4F 4D 20 49 6E 74 65 72 6E 61 74 69 6F 6E 61 6C 20 43 6F 72 70 2E 20 31 39 38 38 2D 31 39 39 35 2E 20 41 6C 6C 20 72 69 67 68 74 73 20 72 65 73 65 72 76 65 64 2E 00 00 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Microsoft_Visual_Cpp_60_DLL_Debug
{
    meta:
        description = "Microsoft Visual C++ 6.0 DLL (Debug)"

    strings:
        $pattern = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 ?? ?? 83 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Microsoft_Visual_Cpp_70_DLL
{
    meta:
        description = "Microsoft Visual C++ 7.0 DLL"

    strings:
        $pattern = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? }
        $pattern_1 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 75 09 83 3D ?? ?? ?? 71 00 EB 26 83 FE 01 74 05 83 FE 02 75 22 A1 ?? }
        $pattern_2 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 0F 84 ?? ?? 00 00 83 FE 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }

    condition:
        uint16(0) == 0x5A4D
        and any of them
}

rule _32Lite_003a_DLL
{
    meta:
        description = "32Lite 0.03a DLL"

    strings:
        $pattern = { 80 7C 24 08 01 75 F4 E9 ?? ?? FF FF 00 10 00 00 0C 00 00 00 06 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? 00 00 ?? ?? 00 00 00 00 00 00 ?? ?? }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule PackMan_v0001
{
    meta:
        description = "PackMan v0.0.0.1"

    strings:
        $pattern = { 60 E8 00 00 00 00 58 8D A8 ?? ?? FF FF 8D 98 ?? ?? ?? FF 8D ?? ?? 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

rule Microsoft_Visual_Cpp_v80
{
    meta:
        description = "Microsoft Visual C++ v8.0"

    strings:
        $pattern = { E8 ?? ?? ?? ?? E9 ?? ?? FF FF }

    condition:
        uint16(0) == 0x5A4D
        and all of them
}

