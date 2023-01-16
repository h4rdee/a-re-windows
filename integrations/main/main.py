import yara, os, pefile, dnfile, threading
import tkinter as tk

from enum import IntEnum
from tkinter import filedialog as fd

from .parsers.dotnet_parser      import DotNetParser
from .parsers.hashes_parser      import HashesParser
from .parsers.rich_header_parser import RichHeaderParser
from .parsers.sections_parser    import SectionsParser
from .parsers.imports_parser     import ImportsParser
from .parsers.exports_parser     import ExportsParser
from .parsers.strings_parser     import StringsParser
from .parsers.overlay_parser     import OverlayParser
from .parsers.yara_parser        import YaraParser

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
        self.__loading_layer = None

    def __sample_loaded_event(self) -> None:
        is_dotnet_sample = False

        self.__loading_layer.set_action('Parsing PE/.NET Structure')
        try: # try to parse pe/dn object
            pe = pefile.PE(data=self.__sample_buffer)
            dn = dnfile.dnPE(data=self.__sample_buffer)

            if dn.net != None:
                is_dotnet_sample = True
                if dn.net.metadata == None:
                    print(
                        "[!] warning: .net sample seems to be corrupted (metadata missing)\n"
                        f"{dn.get_warnings()}"
                    )
                    self.__loading_layer.get_tk_object().place_forget()
                    return

        except pefile.PEFormatError as ex:
            print(f"[!] exception: {ex}")
            self.__loading_layer.get_tk_object().place_forget()
            return

        # send sample loaded event to all integrations
        for integration in self.__integrations:
            integration.sample_loaded_event(self.__sample_buffer)

        # parse sample
        self.__dotnet_parser.update(dn, is_dotnet_sample)
        self.__hashes_parser.update(pe, self.__sample_buffer)
        self.__rich_hdr_parser.update(pe)
        self.__sections_parser.update(pe)
        self.__imports_parser.update(pe)
        self.__exports_parser.update(pe)
        self.__strings_parser.update(self.__sample_buffer)
        self.__overlay_parser.update(pe)
        self.__yara_parser.update(self.__sample_buffer)

        self.__dotnet_parser.parse()   # parse .net info
        self.__hashes_parser.parse()   # parse hashes
        self.__rich_hdr_parser.parse() # parse RICH header
        self.__sections_parser.parse() # parse sections
        self.__imports_parser.parse()  # parse imports
        self.__exports_parser.parse()  # parse exports
        self.__strings_parser.parse()  # parse strings
        self.__overlay_parser.parse()  # parse overlay
        self.__yara_parser.parse()     # parse YARA

        self.__loading_layer.get_tk_object().place_forget()

    def __load_sample_pressed(self) -> None:
        filetypes = (
            ('Sample', '*.bin *.exe *.dll'),
            ('All files', '*.*')
        )

        # show loading indicator
        self.__loading_layer.set_action('Loading Sample')
        dimensions = self.__loading_layer.get_dimensions()
        self.__loading_layer.get_tk_object().place(
            x = dimensions[0], 
            y = dimensions[1],
            width = dimensions[2],
            height = dimensions[3]
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
            self.__loading_layer.get_tk_object().place_forget()
            return

        threading.Thread(target=self.__sample_loaded_event).start()

    def set_window_object(self, window_object) -> None:
        self.__window_object = window_object

        self.__dotnet_parser   = DotNetParser(None, None, self.__window_object)
        self.__hashes_parser   = HashesParser(None, None, self.__window_object)
        self.__rich_hdr_parser = RichHeaderParser(None, self.__window_object)
        self.__sections_parser = SectionsParser(None, self.__window_object)
        self.__imports_parser  = ImportsParser(None, self.__window_object)
        self.__exports_parser  = ExportsParser(None, self.__window_object)
        self.__strings_parser  = StringsParser(None, self.__window_object)
        self.__overlay_parser  = OverlayParser(None, self.__window_object)
        self.__yara_parser     = YaraParser(None, self.__window_object)

    def register_element(self, element) -> None:
        self.__elements.append(element)

    def setup(self) -> None:
        for element in self.__elements:
            if element == None: continue

            tk_object = element.get().get_tk_object()
            element_alias = element.get_alias()

            if element_alias == 'LOADING_LAYER':
                self.__loading_layer = element.get()
            elif element_alias == 'BUTTON_LOAD_SAMPLE':
                tk_object.config(command=self.__load_sample_pressed)
                
    def request_needed_elements(self) -> list:
        return [
            'LOADING_LAYER',
            'BUTTON_LOAD_SAMPLE'
        ]
