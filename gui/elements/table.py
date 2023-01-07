import tkinter as tk

from tksheet import Sheet

class UITable:
    def __init__(self, root_object: tk.Tk, element_scheme: dict) -> None:
        self.__tk_object = tk.Frame(root_object)

        self.__sheet_object = Sheet(
            self.__tk_object,
            theme="dark green",
            show_top_left=False,
            show_row_index=False,
            show_y_scrollbar=False,
            headers=element_scheme['element_headers'],
            data=element_scheme['element_data'],
            width=element_scheme['element_pos']['w']
        )

        self.__tk_object.grid_columnconfigure(0, weight=1)
        self.__tk_object.grid_rowconfigure(0, weight=1)

        self.__sheet_object.enable_bindings("single_select", "copy", "right_click_popup_menu")
        self.__sheet_object.set_all_cell_sizes_to_text()

        # self.__tk_object.grid(row=0, column=0, sticky="nswe")
        self.__sheet_object.grid(row=0, column=0, sticky="nswe")

        self.__tk_object.place(
            x = element_scheme['element_pos']['x'],
            y = element_scheme['element_pos']['y'],
            width = element_scheme['element_pos']['w'],
            height = element_scheme['element_pos']['h']
        )

    def clear(self, fit_to_text_size = True) -> None:
        self.__sheet_object.set_sheet_data([[]])

        if fit_to_text_size:
            self.__sheet_object.set_all_cell_sizes_to_text()
            self.__sheet_object.redraw()

    def update_data(self, data, fit_to_text_size = True) -> None:
        self.__sheet_object.set_sheet_data(data)

        if fit_to_text_size:
            self.__sheet_object.set_all_cell_sizes_to_text()
            self.__sheet_object.redraw()

    def set_column_widths(self, sizes: list) -> None:
        self.__sheet_object.set_column_widths(sizes)
        self.__sheet_object.redraw()

    def get_sheet_object(self) -> Sheet:
        return self.__sheet_object

    def get_tk_object(self) -> tk.Label:
        return self.__tk_object
