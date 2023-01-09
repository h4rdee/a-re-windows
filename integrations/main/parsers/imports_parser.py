import pefile

class ImportsParser:

    def __init__(self, pe: pefile.PE, window_object) -> None:
        self.__pe_object = pe
        self.__win_obj = window_object
        self.__imports_data = list()

        self.__loading_layer = self.__win_obj.get_element_by_alias('LOADING_LAYER').get()

        self.__imports_entries = self.__win_obj.get_element_by_alias('LISTBOX_IMPORTS_ENTRIES').get()
        self.__imports = self.__win_obj.get_element_by_alias('TABLE_IMPORTS').get()

        self.__imports.get_sheet_object().hide(canvas="x_scrollbar")
        self.__imports.get_sheet_object().show(canvas="y_scrollbar")
        
        self.__imports.set_column_widths([370, 50, 50, 70]) # TODO: treat column widths as element property

    def __import_entry_changed_event(self, *args) -> None:
        idx = args[0].widget.curselection()

        if len(idx) != 0:
            self.__imports.update_data(self.__imports_data[idx[0]], False) # update table data
        
        self.__imports.set_column_widths([370, 50, 50, 70])

    def update(self, pe: pefile.PE) -> None:
        self.__imports_entries.get_tk_object().bind(
            '<<ListboxSelect>>', self.__import_entry_changed_event
        )
        self.__pe_object = pe

    def parse(self) -> None:
        self.__loading_layer.set_action('Collecting Imports Info')

        # clear previous results
        self.__imports_entries.clear()
        self.__imports_data.clear()
        self.__imports.clear()
        
        try:
            # fill import entries
            for i, import_entry in enumerate(self.__pe_object.DIRECTORY_ENTRY_IMPORT):

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

        except AttributeError:
            # section-less or malformed PE file - ignore it
            self.__imports.set_column_widths([370, 50, 50, 70])
