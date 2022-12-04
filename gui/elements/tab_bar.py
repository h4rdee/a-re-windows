import tkinter as tk
import tkinter.ttk as ttk

from .tab import UITab

class UITabBar:
    def __init__(self, root_object: tk.Tk, element_scheme: dict) -> None:
        self.__tk_object = ttk.Notebook(root_object)
        self.__tabs = list()

        for tab in element_scheme['tabs']:
            self.__tabs.append(UITab(self.__tk_object, tab))

        self.__tk_object.place(
            x = element_scheme['element_pos']['x'],
            y = element_scheme['element_pos']['y'],
            width = element_scheme['element_pos']['w'],
            height = element_scheme['element_pos']['h']
        )

    def get_tk_object(self) -> ttk.Notebook:
        return self.__tk_object
