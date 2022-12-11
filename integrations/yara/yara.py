from __future__ import absolute_import

import yara
import tkinter as tk

from tkinter import filedialog as fd

class YaraIntegration:
    def __init__(self) -> None:
        self.__elements = list()
        self.__yara_rule = None

    def __load_yara_rule_pressed(self, event) -> None:
        filetypes = (
            ('YARA rule', '*.yar'),
            ('All files', '*.*')
        )

        try:
            filename = fd.askopenfilename(
                title='Select YARA rule',
                initialdir='/',
                filetypes=filetypes
            )
        
            with open(filename, 'r', encoding='utf-8') as yara_rule:
                for element in self.__elements:
                    tk_object = element.get().get_tk_object()
                    element_alias = element.get_alias()
                    if element_alias == 'TEXTBOX_YARA_RULE':
                        tk_object.replace("1.0", tk.END, self.__yara_rule)
                        tk_object.highlight_all()

        except FileNotFoundError:
            print("[!] yara rule wasn't selected")

    def __yara_analyze_pressed(self, event) -> None:
        result = str()
        self.__yara_rule = self.__tk_yara_rule.get("1.0", tk.END)
            
        try: rule = yara.compile(source=self.__yara_rule)
        except yara.SyntaxError as ex:
            print(f"[!] yara error - {ex}")
            return

        for match in rule.match(data=self.__binary_buffer):
            result += f"Sample matched YARA rule {match}\n"

        for element in self.__elements:
            tk_object = element.get().get_tk_object()
            element_alias = element.get_alias()
            if element_alias == 'TEXTBOX_YARA_RESULT':
                tk_object['state'] = 'normal'
                tk_object.replace("1.0", tk.END, result)
                tk_object.highlight_all()
                tk_object['state'] = 'disabled'

    def sample_loaded_event(self, binary_buffer: bytes) -> None:
        self.__binary_buffer = binary_buffer

    def register_element(self, element) -> None:
        self.__elements.append(element)

    def setup_callbacks(self) -> None:
        for element in self.__elements:
            tk_object = element.get().get_tk_object()
            element_alias = element.get_alias()

            if element_alias == 'BUTTON_LOAD_YARA_RULE':
                tk_object.bind("<Button-1>", self.__load_yara_rule_pressed)
            elif element_alias == 'BUTTON_YARA_ANALYZE':
                tk_object.bind("<Button-1>", self.__yara_analyze_pressed)
            elif element_alias == 'TEXTBOX_YARA_RULE':
                self.__tk_yara_rule = tk_object

    def request_needed_elements(self) -> list:
        return [
            'BUTTON_LOAD_YARA_RULE', 
            'BUTTON_YARA_ANALYZE',
            'TEXTBOX_YARA_RULE',
            'TEXTBOX_YARA_RESULT'
        ]
