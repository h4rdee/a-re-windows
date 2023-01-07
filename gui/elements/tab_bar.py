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

    def add_tab(self, tab_object: UITab) -> None:
        self.__tabs.append(tab_object)

    def remove_tab(self, tab_object: UITab) -> None:
        for tab in self.__tabs:
            if tab == tab_object:
                self.__tabs.remove(tab_object)
                tab_object.get_tk_object().destroy()

    def clear_tabs(self) -> None:
        self.__tabs.clear()
        for tab in self.__tabs:
            tab.get_tk_object().destroy()

    def get_all_tabs(self) -> list:
        return self.__tabs

    def get_tk_object(self) -> ttk.Notebook:
        return self.__tk_object
