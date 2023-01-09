import pefile

class ExportsParser:

    def __init__(self, pe: pefile.PE, window_object) -> None:
        self.__pe_object = pe
        self.__win_obj = window_object

        self.__loading_layer = self.__win_obj.get_element_by_alias('LOADING_LAYER').get()

        self.__exports = self.__win_obj.get_element_by_alias('TABLE_EXPORTS').get()
        
        self.__exports.get_sheet_object().hide(canvas="x_scrollbar")
        self.__exports.get_sheet_object().show(canvas="y_scrollbar")
        self.__exports.set_column_widths([450, 100, 50, 70])

    def update(self, pe: pefile.PE) -> None:
        self.__pe_object = pe

    def parse(self) -> None:
        self.__loading_layer.set_action('Collecting Exports Info')

        # clear previous results
        self.__exports.clear()

        exports = list()

        if not hasattr(self.__pe_object, 'DIRECTORY_ENTRY_EXPORT'):
            self.__exports.set_column_widths([450, 100, 50, 70])
            return # there are no exports..
        
        for export_symbol in self.__pe_object.DIRECTORY_ENTRY_EXPORT.symbols:
            export_name = ""
            if export_symbol.name != None:
                export_name = export_symbol.name.decode(encoding='ascii')
                self.__loading_layer.set_sub_action(export_name)
                # TODO: add demangling

            if not hasattr(export_symbol, 'name_offset'):
                export_symbol_name_offset = None
            else:
                export_symbol_name_offset = hex(export_symbol.name_offset)

            exports.append([
                export_name, export_symbol_name_offset,
                export_symbol.ordinal, hex(export_symbol.address)
            ])

        self.__exports.update_data(exports, False) # update table data
        self.__exports.set_column_widths([450, 100, 50, 70])
