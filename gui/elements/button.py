import tkinter as tk

class UIButton:
    def __init__(self, root_object: tk.Tk, element_scheme: dict) -> None:
        self.__alias = element_scheme['element_alias']
        
        self.__tk_object = tk.Button(
            root_object, text=element_scheme['element_text']
        )

        self.__tk_object.place(
            x = element_scheme['element_pos']['x'],
            y = element_scheme['element_pos']['y'],
            width = element_scheme['element_pos']['w'],
            height = element_scheme['element_pos']['h']
        )

    def get_tk_object(self) -> tk.Button:
        return self.__tk_object

    def get_alias(self) -> str:
        return self.__alias

    def __del__(self):
        # print(f"[>] destroying UIButton ({self.__alias}) [{hex(id(self))}]")
        pass
