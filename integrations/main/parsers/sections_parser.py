import os, json, pefile
import tkinter as tk

from tkinter import filedialog as fd
from functools import partial

class SectionsParser:

    def __init__(self, pe: pefile.PE, window_object) -> None:
        self.__pe_object = pe
        self.__win_obj = window_object
        self.__pe_sections_db = None

        self.__loading_layer = self.__win_obj.get_element_by_alias('LOADING_LAYER').get()

        self.__tab_bar_sections_info = self.__win_obj.get_element_by_alias('TAB_BAR_SECTIONS_INFO').get()

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

    def __analyze_section(self, section) -> list:
        section_name = section.Name.decode(encoding='ascii').rstrip('\x00')
        self.__loading_layer.set_sub_action(section_name)

        result = list()

        if self.__pe_sections_db == None:
            signatures_path = os.path.join('integrations', 'main', 'signatures')
            with open(os.path.join(signatures_path, 'pe_sections.json'), 'r') as pe_sections_db:
                self.__pe_sections_db = json.load(pe_sections_db)

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
            "element_data": [[
                hex(section.Misc_VirtualSize), hex(section.VirtualAddress),
                hex(section.SizeOfRawData), hex(section.PointerToRawData),
                hex(section.PointerToRelocations), hex(section.PointerToLinenumbers),
                hex(section.NumberOfRelocations), hex(section.Characteristics)
            ]]
        })

        return result

    def update(self, pe: pefile.PE) -> None:
        self.__pe_object = pe

    def parse(self) -> None:
        self.__loading_layer.set_action('Analyzing PE Sections')
        
        try: # clear previous sections info
            for tab in self.__tab_bar_sections_info.get_all_tabs():
                for sub_element in tab.get_element_scheme()['elements']: # destroy child elements (if any)
                    self.__win_obj.destroy_element_by_alias(sub_element['element_alias'])
                self.__win_obj.destroy_element_by_alias(tab.get_alias())

            self.__tab_bar_sections_info.clear_tabs()

        except tk.TclError:
            pass

        # generate new sections tabs
        for section in self.__pe_object.sections:
            section_name = section.Name.decode(encoding='ascii').rstrip('\x00')

            element = self.__win_obj.generate_element(
                self.__tab_bar_sections_info.get_tk_object(),
                {
                    "element_id": 6,
                    "element_text": section_name,
                    "element_alias": f"TAB_{section_name.upper()}",
                    "element_state": False,
                    "elements": self.__analyze_section(section)
                }
            )
            self.__tab_bar_sections_info.add_tab(element)

        # setup callbacks
        for sub_element in self.__win_obj.get_all_elements():
            sub_element_alias = sub_element.get_alias()
            if 'BUTTON_DUMP_' in sub_element_alias and '_SECTION' in sub_element_alias:
                sub_element.get().get_tk_object().config(
                    command=partial(
                        self.__dump_section_to_file, sub_element_alias, self.__pe_object
                    )
                )
