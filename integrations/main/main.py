import yara, os, hashlib, ppdeep, pefile, json
import tkinter as tk

from enum import IntEnum
from tkinter import filedialog as fd
from functools import partial

class EYaraRuleType(IntEnum):
    RULE_UNKNOWN = -1,
    RULE_COMPILER = 0,
    RULE_PACKER = 1,
    RULE_INSTALLER = 2,
    RULE_CAPABILITIES = 3,
    RULE_PETOOLS = 4,
    RULE_DIE = 5

class MainIntegration:
    def __init__(self, integrations: list) -> None:
        self.__integrations = integrations
        self.__elements = list()

        self.__window_object = None

        self.__tk_compiler_info = None
        self.__tk_packer_info = None
        self.__tk_installer_info = None

        self.__tk_capabilities = None
        self.__tk_signatures = None

        self.__tab_bar_sections_info = None

        self.__hash_sha256 = None
        self.__hash_sha1 = None
        self.__hash_md5 = None
        self.__hash_imphash = None
        self.__hash_ssdeep = None

        self.__pe_sections_db = None

    def __get_rule_type_by_filename(self, filename: str) -> EYaraRuleType:
        if 'compilers' in filename:
            return EYaraRuleType.RULE_COMPILER
        elif 'packers' in filename:
            return EYaraRuleType.RULE_PACKER
        elif 'installers' in filename:
            return EYaraRuleType.RULE_INSTALLER
        elif 'capabilities' in filename:
            return EYaraRuleType.RULE_CAPABILITIES
        elif 'petools' in filename:
            return EYaraRuleType.RULE_PETOOLS
        elif 'die' in filename:
            return EYaraRuleType.RULE_DIE

        return EYaraRuleType.RULE_UNKNOWN

    def __get_info_string_by_rule_type(self, yara_match, rule_type: EYaraRuleType) -> str:
        info = str()
        name = str()
        version = str()

        # name (if any)
        try: name = yara_match[rule_type]['name']
        except: name = "<unknown>"

        # version (if any)
        try: version = f"({yara_match[rule_type]['version']})"
        except: version = "(unknown version)"

        if rule_type == EYaraRuleType.RULE_COMPILER:
            info = f"Compiler info: {name} {version}"
        elif rule_type == EYaraRuleType.RULE_PACKER:
            info = f"Packer info: {name} {version}"
        elif rule_type == EYaraRuleType.RULE_INSTALLER:
            info = f"Installer info: {name} {version}"

        return info

    def __update_sample_info(self, yara_match) -> None:
        rule_type = list(yara_match.keys())[0]
    
        # update capabilities info
        if rule_type == EYaraRuleType.RULE_CAPABILITIES:
            if 'description' in yara_match[rule_type]:
                self.__tk_capabilities.insert(
                    0, yara_match[rule_type]['description']
                )
        elif rule_type == EYaraRuleType.RULE_PETOOLS:
            if 'description' in yara_match[rule_type]:
                self.__tk_signatures.insert(
                    0, f"PE Tools: {yara_match[rule_type]['description']}"
                )
        elif rule_type == EYaraRuleType.RULE_DIE:
            if 'description' in yara_match[rule_type]:
                self.__tk_signatures.insert(
                    0, f"DiE: {yara_match[rule_type]['description']}"
                )
        else: # update meta info
            info_string = self.__get_info_string_by_rule_type(yara_match, rule_type)
            self.__tk_compiler_info.config(text=info_string)

    def __update_hashes(self, pe: pefile.PE) -> None:
        self.__hash_sha256.set_text(hashlib.sha256(self.__sample_buffer).hexdigest(), True)
        self.__hash_sha1.set_text(hashlib.sha1(self.__sample_buffer).hexdigest(), True)
        self.__hash_md5.set_text(hashlib.md5(self.__sample_buffer).hexdigest(), True)
        self.__hash_imphash.set_text(pe.get_imphash(), True)
        self.__hash_ssdeep.set_text(ppdeep.hash(self.__sample_buffer), True)

    def __dump_section_to_file(self, element_alias: str, pe: pefile.PE) -> None:
        section_name = element_alias[len('BUTTON_DUMP_'):-len('_SECTION')].lower()
        for section in pe.sections:
            if section_name in section.Name.decode(encoding='ascii'):
    
                filetypes = (
                    ('Binary dump', '*.bin'),
                    ('All files', '*.*')
                )

                filename = fd.asksaveasfilename(
                    title='Dump section',
                    initialdir='/',
                    filetypes=filetypes
                )
                
                try:
                    with open(filename, 'wb') as section_dump:
                        section_dump.write(section.get_data())
                except FileNotFoundError:
                    print("[!] dump file wasn't selected")
                    return

    def __update_sections_info(self, pe: pefile.PE) -> None:
        def analyze_section(section) -> list:
            result = list()

            if self.__pe_sections_db == None:
                signatures_path = os.path.join('integrations', 'main', 'signatures')
                with open(os.path.join(signatures_path, 'pe_sections.json'), 'r') as pe_sections_db:
                    self.__pe_sections_db = json.load(pe_sections_db)

            section_name = section.Name.decode(encoding='ascii').rstrip('\x00')
            description = "unknown section"

            for section_db_entry in self.__pe_sections_db["sections"]:
                if section_name == section_db_entry["name"]:
                    description = f"Detected: {section_db_entry['type']}\n{section_db_entry['description']}\n"
                    description += f"Entropy: {section.get_entropy()}"

            # add description label
            result.append({
                "element_id": 0,
                "element_alias": f"LABEL_SECTION_{section_name.upper()}_DESCRIPTION",
                "element_text": f"{description}",
                "element_pos": { "x": 10, "y": 10, "w": 0, "h": 0 }
            })

            # add "dump section to file" button
            result.append({
                "element_id": 1,
                "element_alias": f"BUTTON_DUMP_{section_name.upper()}_SECTION",
                "element_text": "Dump section to file",
                "element_pos": { "x": 14, "y": 65, "w": 150, "h": 25 }
            })

            # add table with section info
            result.append({
                "element_id": 7,
                "element_alias": f"TABLE_SECTION_{section_name.upper()}_INFO",
                "element_pos": { "x": 14, "y": 105, "w": 655, "h": 65 },
                "element_headers": [
                    "VirtualSize", "VirtualAddress", "SizeOfRawData", "PointerToRawData",
                    "PointerToRelocations", "PointerToLineNumbers", "NumberOfRelocations",
                    "Characteristics"
                ],
                "element_data": [
                    [
                        hex(section.Misc_VirtualSize),
                        hex(section.VirtualAddress),
                        hex(section.SizeOfRawData),
                        hex(section.PointerToRawData),
                        hex(section.PointerToRelocations),
                        hex(section.PointerToLinenumbers),
                        hex(section.NumberOfRelocations),
                        hex(section.Characteristics)
                    ]
                ]
            })

            return result

        # clear previous sections info
        for tab in self.__tab_bar_sections_info.get_all_tabs():
            for sub_element in tab.get_element_scheme()['elements']: # destroy child elements (if any)
                self.__window_object.destroy_element_by_alias(sub_element['element_alias'])
            self.__window_object.destroy_element_by_alias(tab.get_alias())

        self.__tab_bar_sections_info.clear_tabs()

        # generate new sections tabs
        for section in pe.sections:
            section_name = section.Name.decode(encoding='ascii').rstrip('\x00')

            element = self.__window_object.generate_element(
                self.__tab_bar_sections_info.get_tk_object(),
                {
                    "element_id": 6,
                    "element_text": section_name,
                    "element_alias": f"TAB_{section_name.upper()}",
                    "element_state": False,
                    "elements": analyze_section(section)
                }
            )
            self.__tab_bar_sections_info.add_tab(element)

        # setup callbacks
        for sub_element in self.__window_object.get_all_elements():
            sub_element_alias = sub_element.get_alias()
            if 'BUTTON_DUMP_' in sub_element_alias and '_SECTION' in sub_element_alias:
                sub_element.get().get_tk_object().config(
                    command=partial(
                        self.__dump_section_to_file, sub_element_alias, pe
                    )
                )

    def __sample_loaded_event(self) -> None:
        # send sample loaded event to all integrations
        for integration in self.__integrations:
            integration.sample_loaded_event(self.__sample_buffer)

        # PE object
        pe = pefile.PE(data=self.__sample_buffer)

        # try to detect what we dealing with..
        self.__tk_compiler_info.config(text="Compiler info: <unknown>")
        self.__tk_packer_info.config(text="Packer info: <unknown>")
        self.__tk_installer_info.config(text="Installer info: <unknown>")

        self.__update_hashes(pe) # update hashes
        self.__update_sections_info(pe) # update sections info
        
        # clear previous results
        self.__tk_capabilities.delete(0, self.__tk_capabilities.size())
        self.__tk_signatures.delete(0, self.__tk_signatures.size())

        yara_matches = list()
        yara_rules_dir = os.path.join('integrations', 'main', 'signatures')
        
        # perform yara scan (TODO: cache yara rules instead of reloading them every time)
        for filename in os.listdir(yara_rules_dir):

            if 'pe_sections' in filename: continue # ignore pe_sections db

            yara_rule_type = self.__get_rule_type_by_filename(filename)
            filename = os.path.join(yara_rules_dir, filename)
            
            if os.path.isfile(filename):
                with open(filename, 'r', encoding='utf-8') as yara_rule:
                    try:
                        rule = yara.compile(source=yara_rule.read())
                        for match in rule.match(data=self.__sample_buffer):
                            yara_matches.append({yara_rule_type: match.meta} )

                    except yara.SyntaxError as ex:
                        print(f"[!] yara error, rule {filename} - {ex}")

        # update sample info based on yara matches
        for yara_match in yara_matches:
            self.__update_sample_info(yara_match)

    def __load_sample_pressed(self) -> None:
        filetypes = (
            ('Sample', '*.bin *.exe *.dll'),
            ('All files', '*.*')
        )

        filename = fd.askopenfilename(
            title='Select sample',
            initialdir='/',
            filetypes=filetypes
        )
        
        try:
            with open(filename, 'rb') as sample_buffer:
                self.__sample_buffer = sample_buffer.read()
        except FileNotFoundError:
            print("[!] sample wasn't selected")
            return

        self.__sample_loaded_event()

    def set_window_object(self, window_object) -> None:
        self.__window_object = window_object

    def register_element(self, element) -> None:
        self.__elements.append(element)

    def setup(self) -> None:
        for element in self.__elements:
            tk_object = element.get().get_tk_object()
            element_alias = element.get_alias()

            if element_alias == 'BUTTON_LOAD_SAMPLE':
                tk_object.config(command=self.__load_sample_pressed)
            elif element_alias == 'LABEL_COMPILER_INFO':
                self.__tk_compiler_info = tk_object
            elif element_alias == 'LABEL_PACKER_INFO':
                self.__tk_packer_info = tk_object
            elif element_alias == 'LABEL_INSTALLER_INFO':
                self.__tk_installer_info = tk_object
            elif element_alias == 'LISTBOX_CAPABILITIES':
                self.__tk_capabilities = tk_object
            elif element_alias == 'LISTBOX_SIGNATURES':
                self.__tk_signatures = tk_object
            elif element_alias == 'TEXTBOX_HASH_SHA256':
                self.__hash_sha256 = element.get()
            elif element_alias == 'TEXTBOX_HASH_SHA1':
                self.__hash_sha1 = element.get()
            elif element_alias == 'TEXTBOX_HASH_MD5':
                self.__hash_md5 = element.get()
            elif element_alias == 'TEXTBOX_HASH_IMPHASH':
                self.__hash_imphash = element.get()
            elif element_alias == 'TEXTBOX_HASH_SSDEEP':
                self.__hash_ssdeep = element.get()
            elif element_alias == 'TAB_BAR_SECTIONS_INFO':
                self.__tab_bar_sections_info = element.get()

    def request_needed_elements(self) -> list:
        return [
            'BUTTON_LOAD_SAMPLE', 
            'LABEL_COMPILER_INFO',
            'LABEL_PACKER_INFO',
            'LABEL_INSTALLER_INFO',
            'LISTBOX_CAPABILITIES',
            'LISTBOX_SIGNATURES',
            'TEXTBOX_HASH_SHA256',
            'TEXTBOX_HASH_SHA1',
            'TEXTBOX_HASH_MD5',
            'TEXTBOX_HASH_IMPHASH',
            'TEXTBOX_HASH_SSDEEP',
            'TAB_BAR_SECTIONS_INFO'
        ]
