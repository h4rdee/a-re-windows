import tkinter as tk

class UIListBox:
    def __init__(self, root_object: tk.Tk, element_scheme: dict) -> None:
        self.__tk_object = tk.Listbox(
            root_object
        )
        self.__tk_object.place(
            x = element_scheme['element_pos']['x'],
            y = element_scheme['element_pos']['y'],
            width = element_scheme['element_pos']['w'],
            height = element_scheme['element_pos']['h']
        )

    def add_entry(self, entry: str) -> None:
        self.__tk_object.insert(self.__tk_object.size(), entry)

    def clear(self):
        self.__tk_object.delete(0, tk.END)

    def get_tk_object(self) -> tk.Listbox:
        return self.__tk_object
