import os
import tkinter as tk
import tkinter.font as tkFont

from tkinter import ttk

from .element import Element
from .layout import Layout

class Window:
    def __init__(self, window_scheme: dict) -> None:
        self.__window_obj = tk.Tk()
        self.__window_obj.resizable(False, False)
        self.__window_style = ttk.Style(self.__window_obj)
        self.__alias = window_scheme['window_alias']
        self.__elements = list()

        # include theme from layout
        self.__window_obj.tk.call(
            "source", 
            f'{os.getcwd()}{window_scheme["window_theme"]["relative_path"]}'
        )

        # use theme from layout
        self.__window_style.theme_use(window_scheme['window_theme']['name'])

        # remove silly dashed line which appears when tab is selected
        self.__window_style.configure("Tab", focuscolor=self.__window_style.configure(".")["background"])

        # set window title
        self.__window_obj.title(window_scheme['window_name'])

        # set window dimensions
        self.__window_obj.configure(
            width=window_scheme['window_size']['width'],
            height=window_scheme['window_size']['height']
        )

        # construct elements from layout
        self.__construct_elements(window_scheme)

    def __construct_elements(self, window_scheme: dict) -> None:
        for element_scheme in window_scheme['elements']:
            self.__elements.append(Element(self.__window_obj, element_scheme))

    def get(self) -> tk.Tk:
        return self.__window_obj

    def get_alias(self) -> str:
        return self.__alias

    def get_all_elements(self) -> list:
        return self.__elements

    def get_element_by_alias(self, alias: str) -> Element:
        for element in self.__elements:
            if element.get_alias() == alias:
                return element