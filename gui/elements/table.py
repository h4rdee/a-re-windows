import tkinter as tk

from tksheet import Sheet

class UITable:
    def __init__(self, root_object: tk.Tk, element_scheme: dict) -> None:
        self.__tk_object = tk.Frame(root_object)

        self.sheet = Sheet(
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

        self.sheet.enable_bindings("single_select", "copy", "right_click_popup_menu")
        self.sheet.set_all_cell_sizes_to_text()

        # self.__tk_object.grid(row=0, column=0, sticky="nswe")
        self.sheet.grid(row=0, column=0, sticky="nswe")

        self.__tk_object.place(
            x = element_scheme['element_pos']['x'],
            y = element_scheme['element_pos']['y'],
            width = element_scheme['element_pos']['w'],
            height = element_scheme['element_pos']['h']
        )

    def get_tk_object(self) -> tk.Label:
        return self.__tk_object
