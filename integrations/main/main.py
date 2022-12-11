import yara, os
import tkinter as tk

from enum import IntEnum
from tkinter import filedialog as fd

class EYaraRuleType(IntEnum):
    RULE_UNKNOWN = -1,
    RULE_COMPILER = 0,
    RULE_PACKER = 1,
    RULE_INSTALLER = 2

class MainIntegration:
    def __init__(self, integrations: list) -> None:
        self.__integrations = integrations
        self.__tk_compiler_info = None
        self.__tk_packer_info = None
        self.__tk_installer_info = None
        self.__elements = list()

    def __get_rule_type_by_filename(self, filename: str) -> EYaraRuleType:
        if 'compilers' in filename:
            return EYaraRuleType.RULE_COMPILER
        elif 'packers' in filename:
            return EYaraRuleType.RULE_PACKER
        elif 'installers' in filename:
            return EYaraRuleType.RULE_INSTALLER

        return EYaraRuleType.RULE_UNKNOWN

    def __sample_loaded_event(self) -> None:
        # send sample loaded event to all integrations
        for integration in self.__integrations:
            integration.sample_loaded_event(self.__sample_buffer)

        # and try to detect what we dealing with..
        self.__tk_compiler_info.config(text="Compiler info: <unknown>")
        self.__tk_packer_info.config(text="Packer info: <unknown>")
        self.__tk_installer_info.config(text="Installer info: <unknown>")

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
            if list(yara_match.keys())[0] == EYaraRuleType.RULE_COMPILER:
                # compiler name (if any)
                try: compiler_name = yara_match[EYaraRuleType.RULE_COMPILER]['name']
                except: compiler_name = "<unknown>"

                # compiler version (if any)
                try: compiler_version = f"({yara_match[EYaraRuleType.RULE_COMPILER]['version']})"
                except: compiler_version = "(unknown version)"

                self.__tk_compiler_info.config(
                    text=f"Compiler info: {compiler_name} {compiler_version}"
                )

    def __load_sample_pressed(self, event) -> None:
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

    def setup_callbacks(self) -> None:
        for element in self.__elements:
            tk_object = element.get().get_tk_object()
            element_alias = element.get_alias()

            if element_alias == 'BUTTON_LOAD_SAMPLE':
                tk_object.bind("<Button-1>", self.__load_sample_pressed)
            elif element_alias == 'LABEL_COMPILER_INFO':
                self.__tk_compiler_info = tk_object
            elif element_alias == 'LABEL_PACKER_INFO':
                self.__tk_packer_info = tk_object
            elif element_alias == 'LABEL_INSTALLER_INFO':
                self.__tk_installer_info = tk_object

    def request_needed_elements(self) -> list:
        return [
            'BUTTON_LOAD_SAMPLE', 
            'LABEL_COMPILER_INFO',
            'LABEL_PACKER_INFO',
            'LABEL_INSTALLER_INFO'
        ]
