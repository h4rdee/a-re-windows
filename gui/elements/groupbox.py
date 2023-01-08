import tkinter as tk

class UIGroupBox:
    def __init__(self, root_object: tk.Tk, element_scheme: dict) -> None:
        self.__alias = element_scheme['element_alias']
        self.__element_scheme = element_scheme

        self.__tk_object = tk.LabelFrame(
            root_object, text=element_scheme['element_text'],
            relief=tk.RIDGE
        )
        self.__tk_object.place(
            x = element_scheme['element_pos']['x'],
            y = element_scheme['element_pos']['y'],
            width = element_scheme['element_pos']['w'],
            height = element_scheme['element_pos']['h']
        )

    def get_alias(self) -> str:
        return self.__alias

    def get_element_scheme(self) -> dict:
        return self.__element_scheme

    def get_tk_object(self) -> tk.LabelFrame:
        return self.__tk_object

    def __del__(self):
        # print(f"[>] destroying UIGroupBox ({self.__alias}) [{hex(id(self))}]")
        pass
