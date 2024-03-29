import tkinter as tk
import tkinter.ttk as ttk

class UITab:
    def __init__(self, root_object: tk.Tk, element_scheme: dict) -> None:
        self.__alias = element_scheme['element_alias']
        self.__tk_object = ttk.Frame(root_object)
        self.__element_scheme = element_scheme

        root_object.add(
            self.__tk_object, 
            text=element_scheme['element_text']
        )
    
    def get_alias(self) -> str:
        return self.__alias

    def get_element_scheme(self) -> dict:
        return self.__element_scheme

    def get_tk_object(self) -> ttk.Frame:
        return self.__tk_object

    def __del__(self):
        # print(f"[>] destroying UITab ({self.__alias}) [{hex(id(self))}]")
        pass