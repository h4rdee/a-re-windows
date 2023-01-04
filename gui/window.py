import os
import tkinter as tk
import tkinter.font as tkFont

from tkinter import ttk

from .elements.tab_bar import UITabBar
from .elements.groupbox import UIGroupBox
from .element import Element

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

        # center window (hack!)
        self.__window_obj.eval('tk::PlaceWindow . center')

        # construct elements from layout
        self.__construct_elements(window_scheme)

    def __construct_tab_bar(self, element):
        if not isinstance(element, UITabBar):
            return

        for tab in element.get_all_tabs(): # need to populate its tabs with their elements
            for sub_element in tab.get_element_scheme()['elements']:

                last_element = Element(tab.get_tk_object(), sub_element)
                self.__elements.append(last_element)

                if isinstance(last_element.get(), UIGroupBox): # is appended element a groupbox?
                    for group_element in last_element.get().get_element_scheme()['elements']: # populate as well

                        element_obj = Element(last_element.get().get_tk_object(), group_element)

                        if isinstance(element_obj.get(), UITabBar):
                            self.__elements.append(element_obj)
                            self.__construct_tab_bar(element_obj.get())  
                            continue

                        self.__elements.append(element_obj)

                elif isinstance(last_element.get(), UITabBar): # is there another tab bar?
                    self.__construct_tab_bar(last_element.get())

    def __construct_elements(self, window_scheme: dict) -> None:
        for element_scheme in window_scheme['elements']:
            self.__elements.append(Element(self.__window_obj, element_scheme))
            
            current_element = self.__elements[-1].get()

            if isinstance(current_element, UITabBar): # is last appended element a tab bar?
                self.__construct_tab_bar(current_element)

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