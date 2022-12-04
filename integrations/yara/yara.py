from __future__ import absolute_import

import yara
import tkinter as tk

from tkinter import filedialog as fd

class YaraIntegration:
    def __init__(self) -> None:
        self.__elements = list()

    def __load_yara_rule_pressed(self, event) -> None:
        filetypes = (
            ('YARA rule', '*.yar'),
            ('All files', '*.*')
        )

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
                    self.__yara_rule = yara_rule.read()
                    tk_object.replace("1.0", tk.END, self.__yara_rule)
                    tk_object.highlight_all()

        rule = yara.compile(source=self.__yara_rule)
        # todo

    def __yara_analyze_pressed(self, event) -> None:
        print("YARA ANALYZE PRESSED")

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

    def request_needed_elements(self) -> list:
        return [
            'BUTTON_LOAD_YARA_RULE', 
            'BUTTON_YARA_ANALYZE',
            'TEXTBOX_YARA_RULE',
            'TEXTBOX_YARA_RESULT'
        ]
