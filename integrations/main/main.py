import tkinter as tk

from tkinter import filedialog as fd

class MainIntegration:
    def __init__(self, integrations: list) -> None:
        self.__integrations = integrations
        self.__elements = list()

    def __sample_loaded_event(self) -> None:
        for integration in self.__integrations:
            integration.sample_loaded_event(self.__sample_buffer)

    def __load_sample_pressed(self, event) -> None:
        filetypes = (
            ('Sample', '*.bin *.exe *.dll'),
            ('All files', '*.*')
        )

        try:
            filename = fd.askopenfilename(
                title='Select sample',
                initialdir='/',
                filetypes=filetypes
            )
        
            with open(filename, 'rb') as sample_buffer:
                self.__sample_buffer = sample_buffer.read()

            self.__sample_loaded_event()

        except FileNotFoundError:
            print("[!] sample wasn't selected")

    def register_element(self, element) -> None:
        self.__elements.append(element)

    def setup_callbacks(self) -> None:
        for element in self.__elements:
            tk_object = element.get().get_tk_object()
            element_alias = element.get_alias()
            if element_alias == 'BUTTON_LOAD_SAMPLE':
                tk_object.bind("<Button-1>", self.__load_sample_pressed)

    def request_needed_elements(self) -> list:
        return [
            'BUTTON_LOAD_SAMPLE'
        ]
