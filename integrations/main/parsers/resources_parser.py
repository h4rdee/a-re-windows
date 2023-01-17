import pefile, binascii, threading

class ResourcesParser:

    def __init__(self, pe: pefile.PE, window_object) -> None:
        self.__pe_object = pe
        self.__win_obj = window_object
        self.__resources_data = list()

        self.__loading_layer = self.__win_obj.get_element_by_alias('LOADING_LAYER').get()

        self.__resources_info = self.__win_obj.get_element_by_alias('LABEL_RESOURCE_INFO').get()
        self.__resources_entries = self.__win_obj.get_element_by_alias('LISTBOX_RESOURCES_ENTRIES').get()
        self.__resources = self.__win_obj.get_element_by_alias('TABLE_RESOURCE_HEX').get()

        self.__resources.get_sheet_object().hide(canvas="x_scrollbar")
        self.__resources.get_sheet_object().show(canvas="y_scrollbar")
        
        self.__resources.set_column_widths([
            25, 25, 25, 25, 25, 25, 25, 25, 
            25, 25, 25, 25, 25, 25, 25, 25, 130
        ]) # TODO: treat column widths as element property

    def __resource_entry_changed_event(self, *args) -> None:
        idx = args[0].widget.curselection()

        if len(idx) != 0:
            resource_data = self.__resources_data[idx[0]]
            self.__resources.update_data(resource_data[5])
            self.__resources_info.get_tk_object().config(
                text = f"Resource: {resource_data[0]}; Offset: {resource_data[1]}; " \
                f"Size: {resource_data[2]}\nLang: {resource_data[3]}; SubLang: {resource_data[4]}"
            )
        
        self.__resources.set_column_widths([
            25, 25, 25, 25, 25, 25, 25, 25, 
            25, 25, 25, 25, 25, 25, 25, 25, 130
        ])

    def __update_resource_entries(self) -> None:
        self.__resources_data.clear()

        if hasattr(self.__pe_object, 'DIRECTORY_ENTRY_RESOURCE'):
            for entry in self.__pe_object.DIRECTORY_ENTRY_RESOURCE.entries:
                
                if entry.name is not None:
                    name = str(entry.name)
                else:
                    name = str(pefile.RESOURCE_TYPE.get(entry.struct.Id))

                if name is None:
                    name = str(entry.struct.Id)

                if hasattr(entry, 'directory'):
                    for resource_id in entry.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_entry in resource_id.directory.entries:

                                data = self.__pe_object.get_data(
                                    resource_entry.data.struct.OffsetToData, 
                                    resource_entry.data.struct.Size
                                )

                                lang = pefile.LANG.get(
                                    resource_entry.data.lang, None
                                )

                                sublang = pefile.get_sublang_name_for_lang(
                                    resource_entry.data.lang, 
                                    resource_entry.data.sublang
                                )

                                offset = ('%-8s' % hex(resource_entry.data.struct.OffsetToData)).strip()
                                size = ('%-8s' % hex(resource_entry.data.struct.Size)).strip()

                                self.__resources_entries.add_entry(name)

                                self.__resources_data.append([
                                    name, offset, size, 
                                    lang, sublang, []
                                ])

                                data_offset = 0
                                for _ in range(0, len(data), 16):
                                    overlay_chunk = bytearray(data[data_offset : data_offset + 16])

                                    if len(overlay_chunk) != 16:
                                        overlay_chunk.extend(b'\x00' * (16 - len(overlay_chunk)))

                                    hexed_chunk = binascii.hexlify(overlay_chunk, ' ').decode('ascii', 'ignore').split(' ')
                                    hexed_chunk.append(overlay_chunk.decode('ascii', 'ignore').replace('\x00', '.').replace('\n', ''))

                                    self.__resources_data[-1][-1].append(hexed_chunk)

                                    data_offset += 16

        #print(self.__resources_data)
        # self.__resources.update_data(self.__resources_data)

    def update(self, pe: pefile.PE) -> None:
        self.__resources_entries.get_tk_object().bind(
            '<<ListboxSelect>>', 
            self.__resource_entry_changed_event
        )
        self.__pe_object = pe

    def parse(self) -> None:
        # clear previous results
        self.__resources_entries.clear()
        self.__resources_data.clear()
        self.__resources.clear()

        self.__resources_info.get_tk_object().config(text = "Resources not found")

        self.__resources.set_column_widths([
            25, 25, 25, 25, 25, 25, 25, 25, 
            25, 25, 25, 25, 25, 25, 25, 25, 130
        ])

        if not hasattr(self.__pe_object, 'DIRECTORY_ENTRY_RESOURCE'):
            return # we don't have any resources in binary

        self.__loading_layer.set_action('Parsing Resources')

        #threading.Thread(target=self.__update_resource_entries).start()
        self.__update_resource_entries()

        self.__resources.get_sheet_object().enable_bindings("drag_select")

        def set_data():
            # set data for first found imports entry
            self.__resources_entries.get_tk_object().select_set(0)
            self.__resources_entries.get_tk_object().event_generate("<<ListboxSelect>>")
        
        threading.Thread(target=set_data).start()
