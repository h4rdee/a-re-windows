import tkinter as tk

class UILabel:
    def __init__(self, root_object: tk.Tk, element_scheme: dict) -> None:
        self.__tk_object = tk.Label(
            root_object, text=element_scheme['element_text'],
            justify=tk.LEFT
        )
        self.__tk_object.place(
            x = element_scheme['element_pos']['x'],
            y = element_scheme['element_pos']['y']
        )

    def get_tk_object(self) -> tk.Label:
        return self.__tk_object
