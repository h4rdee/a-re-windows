import yara, os, hashlib, ppdeep, pefile, dnfile, json, re, threading
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
        self.__imports_data = list()

        self.__window_object = None
        self.__loading_layer = None

        self.__tk_compiler_info = None
        self.__tk_packer_info = None
        self.__tk_installer_info = None
        self.__rich_header_info = None

        self.__tk_capabilities = None
        self.__tk_signatures = None

        self.__tab_bar_sample_info = None
        self.__tab_bar_sections_info = None
        self.__tab_bar_dotnet_info = None

        self.__table_strings = None
        self.__table_user_strings = None
        self.__table_guids = None

        self.__tab_dotnet = None

        self.__imports_entries = None
        self.__imports = None
        self.__exports = None
        self.__strings = None

        self.__hash_sha256 = None
        self.__hash_sha1 = None
        self.__hash_md5 = None
        self.__hash_imphash = None
        self.__hash_rich = None
        self.__hash_ssdeep = None

        self.__pe_sections_db = None
        self.__comp_id_db = None

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
        self.__loading_layer.set_action('Updating General Info')

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
        self.__loading_layer.set_action('Updating Hashes')

        self.__loading_layer.set_sub_action('Calculating SHA256')
        self.__hash_sha256.set_text(hashlib.sha256(self.__sample_buffer).hexdigest(), True)

        self.__loading_layer.set_sub_action('Calculating SHA1')
        self.__hash_sha1.set_text(hashlib.sha1(self.__sample_buffer).hexdigest(), True)

        self.__loading_layer.set_sub_action('Calculating MD5')
        self.__hash_md5.set_text(hashlib.md5(self.__sample_buffer).hexdigest(), True)

        self.__loading_layer.set_sub_action('Calculating IMPHASH')
        self.__hash_imphash.set_text(pe.get_imphash(), True)
        
        self.__loading_layer.set_sub_action('Calculating RICH Header Hash')
        self.__hash_rich.set_text(pe.get_rich_header_hash(), True)
        
        # self.__loading_layer.set_sub_action('Calculating SSDEEP')
        # self.__hash_ssdeep.set_text(ppdeep.hash(self.__sample_buffer), True)

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

    def __update_rich_header_info(self, pe: pefile.PE) -> None:
        def analyze_rich_comp_id(rich_field: int) -> str:
            if self.__comp_id_db == None:
                signatures_path = os.path.join('integrations', 'main', 'signatures')
                with open(os.path.join(signatures_path, 'comp_id.json'), 'r') as comp_id_db:
                    self.__comp_id_db = json.load(comp_id_db)

            for comp_id in self.__comp_id_db["data"]:
                if int(comp_id['comp_id'], 16) == rich_field:
                    return comp_id['description']

        self.__loading_layer.set_action('Parsing PE RICH Header')

        # clear previous results
        self.__rich_header_info.clear()

        rich_header = pe.parse_rich_header()
        if rich_header is None:
            return
        
        rich_fields = rich_header.get("values", None)
        if len(rich_fields) % 2 != 0:
            return

        rich_infos = list()
        compid = None

        for rich_field in rich_fields:
            if rich_fields.index(rich_field) % 2 == 0:
                compid = analyze_rich_comp_id(rich_field)
            else:
                if compid:
                    self.__loading_layer.set_sub_action(compid)
                    rich_infos.append(f"{compid}; count = {rich_field}")
                    compid = None

        for rich_info in rich_infos:
            self.__rich_header_info.add_entry(rich_info)

    def __update_sections_info(self, pe: pefile.PE) -> None:
        def analyze_section(section) -> list:
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

        self.__loading_layer.set_action('Analyzing PE Sections')

        # clear previous sections info
        try:
            for tab in self.__tab_bar_sections_info.get_all_tabs():
                for sub_element in tab.get_element_scheme()['elements']: # destroy child elements (if any)
                    self.__window_object.destroy_element_by_alias(sub_element['element_alias'])
                self.__window_object.destroy_element_by_alias(tab.get_alias())

            self.__tab_bar_sections_info.clear_tabs()

        except tk.TclError:
            pass

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

    def __import_entry_changed_event(self, *args) -> None:
        idx = args[0].widget.curselection()

        if len(idx) != 0:
            self.__imports.update_data(self.__imports_data[idx[0]], False) # update table data
        
        self.__imports.set_column_widths([370, 50, 50, 70])

    def __update_imports_info(self, pe: pefile.PE) -> None:
        self.__loading_layer.set_action('Collecting Imports Info')

        # clear previous results
        self.__imports_entries.clear()
        self.__imports_data.clear()
        self.__imports.clear()
        
        # fill import entries
        for i, import_entry in enumerate(pe.DIRECTORY_ENTRY_IMPORT):

            self.__imports_entries.add_entry(
                import_entry.dll.decode(encoding='ascii')
            )

            self.__imports_data.append([[]]) # hack

            # fill imports
            for _import in import_entry.imports:

                import_name = ""
                if _import.name != None:
                    import_name = _import.name.decode(encoding='ascii')
                    self.__loading_layer.set_sub_action(import_name)
                    # TODO: add demangling

                import_thunk = ""
                if _import.hint_name_table_rva != None:
                    import_thunk = hex(_import.hint_name_table_rva)

                import_hint = ""
                if _import.hint != None:
                    import_hint = hex(_import.hint)

                self.__imports_data[i].append([
                    import_name, import_thunk,
                    _import.ordinal, import_hint
                ])

            self.__imports_data[-1].pop(0) # TODO: get rid of this
        
        # set data for first found imports entry
        self.__imports_entries.get_tk_object().select_set(0)
        self.__imports_entries.get_tk_object().event_generate("<<ListboxSelect>>")

    def __update_exports_info(self, pe: pefile.PE) -> None:
        self.__loading_layer.set_action('Collecting Exports Info')

        # clear previous results
        self.__exports.clear()

        exports = list()

        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            self.__exports.set_column_widths([470, 80, 50, 70])
            return # there are no exports..
        
        for export_symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            export_name = ""
            if export_symbol.name != None:
                export_name = export_symbol.name.decode(encoding='ascii')
                self.__loading_layer.set_sub_action(export_name)
                # TODO: add demangling

            exports.append([
                export_name, hex(export_symbol.name_offset),
                export_symbol.ordinal, hex(export_symbol.address)
            ])

        self.__exports.update_data(exports, False) # update table data
        self.__exports.set_column_widths([470, 80, 50, 70])

    def __update_strings_info(self, pe: pefile.PE) -> None:
        self.__loading_layer.set_action('Collecting Strings')
        self.__loading_layer.set_sub_action("")

        # clear previous results
        self.__strings.clear()

        strings_data = list()

        strings_matches = re.finditer(
            b'[\x20-\x7e]{4,}', 
            self.__sample_buffer
        )

        for match in strings_matches:
            string_file_offset = match.regs[0][0]
            decoded_string = match.group().decode('ascii')
            string_size = len(decoded_string)
            string_type = 'ascii'

            strings_data.append([
                decoded_string, string_file_offset,
                string_size, string_type
            ])

        self.__strings.update_data(strings_data, False)
        self.__strings.set_column_widths([485, 80, 40, 60])

    def __update_dotnet_info(self, dn: dnfile.dnPE, is_dotnet_sample: bool) -> None:

        def analyze_md_tables(stream: dnfile.stream.MetaDataTables) -> None:
            self.__loading_layer.set_sub_action('Analyzing Metadata Tables')

            stream_name = stream.struct.Name.decode(encoding='ascii')
            self.__tab_bar_dotnet_info['tabs'][0]['elements'][0]['tabs'].append(
                {
                    "element_id": 6,
                    "element_text": stream_name,
                    "element_alias": f"TAB_{stream_name.upper()}",
                    "element_state": False,
                    "elements": []
                }
            )

        def analyze_strings_heap(stream: dnfile.stream.StringsHeap) -> None:
            self.__loading_layer.set_sub_action('Analyzing Strings Heap')
            stream_name = stream.struct.Name.decode(encoding='ascii')

            result = list()
            raw_data = stream.get_data_at_offset(0, stream.sizeof())
            
            for string in raw_data.split(b'\x00'):
                decoded_string = string.decode(encoding='utf-8')
                result.append([decoded_string, len(decoded_string)])

            self.__table_strings = {
                "element_id": 7,
                "element_alias": "TABLE_DOTNET_STRINGS",
                "element_pos": { "x": 12, "y": 12, "w": 682, "h": 198 },
                "element_headers": [ "String", "Size" ],
                "element_data": result
            }

            self.__tab_bar_dotnet_info['tabs'][0]['elements'][0]['tabs'].append(
                {
                    "element_id": 6,
                    "element_text": stream_name,
                    "element_alias": f"TAB_{stream_name.upper()}",
                    "element_state": False,
                    "elements": [ self.__table_strings ]
                }
            )


        def analyze_us_heap(stream: dnfile.stream.UserStringHeap) -> None:
            self.__loading_layer.set_sub_action('Analyzing UserStrings Heap')

            stream_name = stream.struct.Name.decode(encoding='ascii')
            user_strings = list()

            self.__table_user_strings = {
                "element_id": 7,
                "element_alias": "TABLE_DOTNET_USERSTRINGS",
                "element_pos": { "x": 12, "y": 12, "w": 682, "h": 198 },
                "element_headers": [ "String", "Heap Offset", "Size" ],
                "element_data": []
            }

            # collect userstrings
            size = stream.sizeof()  # get the size of the stream
            offset = 1 # the first entry (the first byte in the stream) is an empty string, so skip it
           
            while offset < size: # while there is still data in the stream
                # read the raw string bytes, and provide the number of bytes to read (includes the encoded length)
                ret = stream.get_with_size(offset)

                if ret is None:
                    offset += readlen
                    continue

                buf, readlen = ret

                try:
                    user_string = buf.decode(
                        encoding='utf-16', 
                        errors='ignore'
                    )

                    user_strings.append([
                        user_string, hex(offset), 
                        len(user_string) # readlen
                    ])

                except UnicodeDecodeError:
                    offset += readlen
                    continue

                offset += readlen  # continue to the next entry

            self.__table_user_strings["element_data"] = user_strings

            self.__tab_bar_dotnet_info['tabs'][0]['elements'][0]['tabs'].append(
                {
                    "element_id": 6,
                    "element_text": stream_name,
                    "element_alias": f"TAB_{stream_name.upper()}",
                    "element_state": False,
                    "elements": [ self.__table_user_strings ]
                }
            )

        def analyze_guid_heap(stream: dnfile.stream.GuidHeap) -> None:
            self.__loading_layer.set_sub_action('Analyzing GUID Heap')

            stream_name = stream.struct.Name.decode(encoding='ascii')
            guids = list()
            guid_index = 1

            while True:
                try:
                    offset = (guid_index - 1) * (128 // 8)
                    guids.append([stream.get(guid_index), hex(offset), guid_index])
                    guid_index += 1
                except IndexError:
                    break

            self.__table_guids = {
                "element_id": 7,
                "element_alias": "TABLE_DOTNET_GUIDS",
                "element_pos": { "x": 12, "y": 12, "w": 682, "h": 198 },
                "element_headers": [ "String", "Heap Offset", "Index" ],
                "element_data": guids
            }

            self.__tab_bar_dotnet_info['tabs'][0]['elements'][0]['tabs'].append(
                {
                    "element_id": 6,
                    "element_text": stream_name,
                    "element_alias": f"TAB_{stream_name.upper()}",
                    "element_state": False,
                    "elements": [ self.__table_guids ]
                }
            )

        def analyze_dot_net(dn: dnfile.dnPE) -> list:
            self.__loading_layer.set_action('Analyzing .NET structure')
            result = list()

            self.__tab_bar_dotnet_info = {
                "element_id": 2,
                "element_alias": "TAB_BAR_DOTNET_INFO",
                "element_pos": { "x": 10, "y": 10, "w": 708, "h": 253 },
                "tabs": [ 
                    {
                        "element_id": 6,
                        "element_text": "Streams",
                        "element_alias": "TAB_DOTNET_METADATA_INFO",
                        "element_state": False,
                        "elements": [{
                            "element_id": 2,
                            "element_alias": "TAB_BAR_STREAMS_INFO",
                            "element_pos": { "x": 10, "y": 10, "w": 730, "h": 300 },
                            "tabs": []
                        }]
                    }
                ]
            }

            for stream in dn.net.metadata.streams_list:
                if isinstance(stream, dnfile.stream.MetaDataTables):
                    analyze_md_tables(stream)
                elif isinstance(stream, dnfile.stream.StringsHeap):
                    analyze_strings_heap(stream)
                elif isinstance(stream, dnfile.stream.UserStringHeap):
                    analyze_us_heap(stream)
                elif isinstance(stream, dnfile.stream.GuidHeap):
                    analyze_guid_heap(stream)
                else:
                    stream_name = stream.struct.Name.decode(encoding='ascii')
                    self.__tab_bar_dotnet_info['tabs'][0]['elements'][0]['tabs'].append(
                        {
                            "element_id": 6,
                            "element_text": stream_name,
                            "element_alias": f"TAB_{stream_name.upper()}",
                            "element_state": False,
                            "elements": []
                        }
                    )

            result.append(self.__tab_bar_dotnet_info)
            return result

        # clear previous results
        self.__tab_bar_sample_info.remove_tab(self.__tab_dotnet)
        self.__window_object.destroy_element_by_alias('TABLE_DOTNET_STRINGS')
        self.__window_object.destroy_element_by_alias('TABLE_DOTNET_USERSTRINGS')
        self.__window_object.destroy_element_by_alias('TABLE_DOTNET_GUIDS')
        
        if not is_dotnet_sample:
            return

        # create separate .net tab
        self.__tab_dotnet = self.__window_object.generate_element(
            self.__tab_bar_sample_info.get_tk_object(),
            {
                "element_id": 6,
                "element_text": ".NET",
                "element_alias": "TAB_DOTNET_INFO",
                "element_state": False,
                "elements": analyze_dot_net(dn)
            }
        )

        self.__loading_layer.set_sub_action('')
        
        self.__tab_bar_dotnet_info = self.__window_object.get_element_by_alias('TAB_BAR_DOTNET_INFO').get()
        self.__tab_bar_sample_info.add_tab(self.__tab_dotnet)

        # format tables
        self.__table_user_strings = self.__window_object.get_element_by_alias('TABLE_DOTNET_USERSTRINGS').get()
        self.__table_user_strings.get_sheet_object().hide(canvas="x_scrollbar")
        self.__table_user_strings.get_sheet_object().show(canvas="y_scrollbar")
        self.__table_user_strings.set_column_widths([535, 80, 40])

        self.__table_strings = self.__window_object.get_element_by_alias('TABLE_DOTNET_STRINGS').get()
        self.__table_strings.get_sheet_object().hide(canvas="x_scrollbar")
        self.__table_strings.get_sheet_object().show(canvas="y_scrollbar")
        self.__table_strings.set_column_widths([535, 120])

        self.__table_strings = self.__window_object.get_element_by_alias('TABLE_DOTNET_GUIDS').get()
        self.__table_strings.get_sheet_object().hide(canvas="x_scrollbar")
        self.__table_strings.get_sheet_object().show(canvas="y_scrollbar")
        self.__table_strings.set_column_widths([545, 80, 40])

    def __sample_loaded_event(self) -> None:
        is_dotnet_sample = False

        self.__loading_layer.set_action('Parsing PE/.NET Structure')
        try: # try to parse pe/dn object
            pe = pefile.PE(data=self.__sample_buffer)
            dn = dnfile.dnPE(data=self.__sample_buffer)

            if dn.net != None:
                is_dotnet_sample = True

        except pefile.PEFormatError as ex:
            print(f"[!] exception: {ex}")
            self.__loading_layer.get_tk_object().place_forget()
            return

        # send sample loaded event to all integrations
        for integration in self.__integrations:
            integration.sample_loaded_event(self.__sample_buffer)

        # try to detect what we dealing with..
        self.__tk_compiler_info.config(text="Compiler info: <unknown>")
        self.__tk_packer_info.config(text="Packer info: <unknown>")
        self.__tk_installer_info.config(text="Installer info: <unknown>")

        self.__update_dotnet_info(dn, is_dotnet_sample) # update dotnet info
        self.__update_hashes(pe) # update hashes
        self.__update_rich_header_info(pe) # update RICH header info
        self.__update_sections_info(pe) # update sections info
        self.__update_imports_info(pe) # update imports
        self.__update_exports_info(pe) # update exports
        self.__update_strings_info(pe) # update strings info
        
        # clear previous results
        self.__tk_capabilities.delete(0, self.__tk_capabilities.size())
        self.__tk_signatures.delete(0, self.__tk_signatures.size())

        yara_matches = list()
        yara_rules_dir = os.path.join('integrations', 'main', 'signatures')
        
        # perform yara scan (TODO: cache yara rules instead of reloading them every time)
        for filename in os.listdir(yara_rules_dir):

            if 'pe_sections' in filename: continue # ignore pe_sections db
            if 'comp_id' in filename: continue # ignore comp_id db

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
            elif element_alias == 'LABEL_COMPILER_INFO':
                self.__tk_compiler_info = tk_object
            elif element_alias == 'LABEL_PACKER_INFO':
                self.__tk_packer_info = tk_object
            elif element_alias == 'LABEL_INSTALLER_INFO':
                self.__tk_installer_info = tk_object
            elif element_alias == 'LISTBOX_RICH_HEADER_INFO':
                self.__rich_header_info = element.get()
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
            elif element_alias == 'TEXTBOX_HASH_RICH':
                self.__hash_rich = element.get()
            elif element_alias == 'TEXTBOX_HASH_SSDEEP':
                self.__hash_ssdeep = element.get()
            elif element_alias == 'TAB_BAR_SAMPLE_INFO':
                self.__tab_bar_sample_info = element.get()
            elif element_alias == 'TAB_BAR_SECTIONS_INFO':
                self.__tab_bar_sections_info = element.get()
            elif element_alias == 'LISTBOX_IMPORTS_ENTRIES':
                self.__imports_entries = element.get()
                self.__imports_entries.get_tk_object().bind(
                    '<<ListboxSelect>>', 
                    self.__import_entry_changed_event
                )
            elif element_alias == 'TABLE_IMPORTS':
                self.__imports = element.get()
                element.get().get_sheet_object().hide(canvas="x_scrollbar")
                element.get().get_sheet_object().show(canvas="y_scrollbar")
                element.get().set_column_widths([370, 50, 50, 70]) # TODO: treat column widths as element property

            elif element_alias == 'TABLE_EXPORTS':
                self.__exports = element.get()
                element.get().get_sheet_object().hide(canvas="x_scrollbar")
                element.get().get_sheet_object().show(canvas="y_scrollbar")
                element.get().set_column_widths([470, 80, 50, 70])

            elif element_alias == 'TABLE_STRINGS':
                self.__strings = element.get()
                element.get().get_sheet_object().hide(canvas="x_scrollbar")
                element.get().get_sheet_object().show(canvas="y_scrollbar")
                element.get().set_column_widths([485, 80, 40, 60])
                
    def request_needed_elements(self) -> list:
        return [
            'LOADING_LAYER',
            'BUTTON_LOAD_SAMPLE', 
            'LABEL_COMPILER_INFO',
            'LABEL_PACKER_INFO',
            'LABEL_INSTALLER_INFO',
            'LISTBOX_RICH_HEADER_INFO',
            'LISTBOX_CAPABILITIES',
            'LISTBOX_SIGNATURES',
            'TEXTBOX_HASH_SHA256',
            'TEXTBOX_HASH_SHA1',
            'TEXTBOX_HASH_MD5',
            'TEXTBOX_HASH_IMPHASH',
            'TEXTBOX_HASH_RICH',
            'TEXTBOX_HASH_SSDEEP',
            'TAB_BAR_SAMPLE_INFO',
            'TAB_BAR_SECTIONS_INFO',
            'LISTBOX_IMPORTS_ENTRIES',
            'TABLE_IMPORTS',
            'TABLE_EXPORTS',
            'TABLE_STRINGS'
        ]
