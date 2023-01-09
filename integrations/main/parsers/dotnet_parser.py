import dnfile

class DotNetParser:

    def __init__(self, dn: dnfile.dnPE, is_dotnet_sample: bool, window_object) -> None:
        self.__dn_object = dn
        self.__is_dotnet_sample = is_dotnet_sample
        self.__win_obj = window_object

        self.__loading_layer = self.__win_obj.get_element_by_alias('LOADING_LAYER').get()

        self.__tab_bar_sample_info = self.__win_obj.get_element_by_alias('TAB_BAR_SAMPLE_INFO').get()
        self.__tab_bar_dotnet_info = None

        self.__tab_dotnet = None

        self.__table_user_strings = None
        self.__table_strings = None
        self.__table_guids = None

    def __format_table(self, table_field, alias: str, column_widths: list) -> None:
        table_element = self.__win_obj.get_element_by_alias(alias)

        if table_element:
            table_field = table_element.get()
            table_field.get_sheet_object().hide(canvas="x_scrollbar")
            table_field.get_sheet_object().show(canvas="y_scrollbar")
            table_field.set_column_widths(column_widths)

    def __analyze_md_tables(self, stream: dnfile.stream.MetaDataTables) -> None:
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

    def __analyze_strings_heap(self, stream: dnfile.stream.StringsHeap) -> None:
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

    def __analyze_us_heap(self, stream: dnfile.stream.UserStringHeap) -> None:
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

    def __analyze_guid_heap(self, stream: dnfile.stream.GuidHeap) -> None:
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
    
    def __analyze_dotnet(self) -> None:
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

        for stream in self.__dn_object.net.metadata.streams_list:
            if isinstance(stream, dnfile.stream.MetaDataTables):
                self.__analyze_md_tables(stream)
            elif isinstance(stream, dnfile.stream.StringsHeap):
                self.__analyze_strings_heap(stream)
            elif isinstance(stream, dnfile.stream.UserStringHeap):
                self.__analyze_us_heap(stream)
            elif isinstance(stream, dnfile.stream.GuidHeap):
                self.__analyze_guid_heap(stream)
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

    def update(self, dn: dnfile.dnPE, is_dotnet_sample: bool) -> None:
        self.__dn_object = dn
        self.__is_dotnet_sample = is_dotnet_sample

    def parse(self) -> None:
        # clear previous results
        self.__tab_bar_sample_info.remove_tab(self.__tab_dotnet)

        self.__win_obj.destroy_element_by_alias('TABLE_DOTNET_STRINGS')
        self.__win_obj.destroy_element_by_alias('TABLE_DOTNET_USERSTRINGS')
        self.__win_obj.destroy_element_by_alias('TABLE_DOTNET_GUIDS')
        
        if not self.__is_dotnet_sample:
            return # nothing to parse

        # create separate .net tab
        self.__tab_dotnet = self.__win_obj.generate_element(
            self.__tab_bar_sample_info.get_tk_object(),
            {
                "element_id": 6,
                "element_text": ".NET",
                "element_alias": "TAB_DOTNET_INFO",
                "element_state": False,
                "elements": self.__analyze_dotnet()
            }
        )

        self.__loading_layer.set_sub_action('')
        
        self.__tab_bar_dotnet_info = self.__win_obj.get_element_by_alias('TAB_BAR_DOTNET_INFO').get()
        self.__tab_bar_sample_info.add_tab(self.__tab_dotnet)

        # format tables
        self.__format_table(self.__table_user_strings, 'TABLE_DOTNET_USERSTRINGS', [535, 80, 40])
        self.__format_table(self.__table_strings, 'TABLE_DOTNET_STRINGS', [535, 120])
        self.__format_table(self.__table_guids, 'TABLE_DOTNET_GUIDS', [545, 80, 40])
