import yara, os
import tkinter as tk

from enum import IntEnum
from tkinter import filedialog as fd

class EYaraRuleType(IntEnum):
    RULE_UNKNOWN = -1,
    RULE_COMPILER = 0,
    RULE_PACKER = 1,
    RULE_INSTALLER = 2,
    RULE_CAPABILITIES = 3

class MainIntegration:
    def __init__(self, integrations: list) -> None:
        self.__integrations = integrations
        self.__elements = list()

        self.__tk_compiler_info = None
        self.__tk_packer_info = None
        self.__tk_installer_info = None
        self.__tk_capabilities = None

    def __get_rule_type_by_filename(self, filename: str) -> EYaraRuleType:
        if 'compilers' in filename:
            return EYaraRuleType.RULE_COMPILER
        elif 'packers' in filename:
            return EYaraRuleType.RULE_PACKER
        elif 'installers' in filename:
            return EYaraRuleType.RULE_INSTALLER
        elif 'capabilities' in filename:
            return EYaraRuleType.RULE_CAPABILITIES

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
        else: # update meta info
            info_string = self.__get_info_string_by_rule_type(yara_match, rule_type)
            self.__tk_compiler_info.config(text=info_string)

    def __sample_loaded_event(self) -> None:
        # send sample loaded event to all integrations
        for integration in self.__integrations:
            integration.sample_loaded_event(self.__sample_buffer)

        # and try to detect what we dealing with..
        self.__tk_compiler_info.config(text="Compiler info: <unknown>")
        self.__tk_packer_info.config(text="Packer info: <unknown>")
        self.__tk_installer_info.config(text="Installer info: <unknown>")
        self.__tk_capabilities.delete(0, self.__tk_capabilities.size())

        yara_matches = list()
        yara_rules_dir = os.path.join('integrations', 'main', 'signatures')
        
        for filename in os.listdir(yara_rules_dir):
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

    def request_needed_elements(self) -> list:
        return [
            'BUTTON_LOAD_SAMPLE', 
            'LABEL_COMPILER_INFO',
            'LABEL_PACKER_INFO',
            'LABEL_INSTALLER_INFO',
            'LISTBOX_CAPABILITIES'
        ]
