import os, time
import tkinter as tk
import tkinter.font as tkFont

from threading import Thread
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

        # create loading layer
        self.__construct_loading_layer()

    def __animate_loading_layer(self) -> None:
        loading_animation = [
            "[□□□□□□□□□□□]", "[■□□□□□□□□□□]", "[■■□□□□□□□□□]", 
            "[■■■□□□□□□□□]", "[■■■■□□□□□□□]", "[■■■■■□□□□□□]", 
            "[■■■■■■□□□□□]", "[■■■■■■■□□□□]", "[■■■■■■■■□□□]", 
            "[■■■■■■■■■□□]", "[■■■■■■■■■■□]", "[■■■■■■■■■■■]"
        ]

        loading_layer = self.get_element_by_alias('LOADING_LAYER').get()
        animation_label = self.get_element_by_alias('LABEL_LOADING').get().get_tk_object()

        while True:
            try:
                action = loading_layer.get_action()
                sub_action = loading_layer.get_sub_action()
                for index, animation in enumerate(loading_animation):
                    animation_label.config(text=f"{action}\n{sub_action}\n{animation}")
                    time.sleep(0.06)
                for index in range(len(loading_animation) - 1, 0, -1):
                    animation_label.config(text=f"{action}\n{sub_action}\n{loading_animation[index]}")
                    time.sleep(0.06)

            except RuntimeError: # ¯\_(ツ)_/¯
                continue

    def __construct_loading_layer(self) -> None:
        win_width = self.__window_obj.winfo_width()
        win_height = self.__window_obj.winfo_height()

        self.__elements.append(
            Element(
                self.__window_obj, 
                {
                    "element_id": -1,
                    "element_alias": "LOADING_LAYER",
                    "element_pos": {
                        "x": 0, "y": 0, 
                        "w": win_width,
                        "h": win_height
                    }
                }
            )
        )

        tk_loading_layer = self.get_element_by_alias('LOADING_LAYER').get().get_tk_object()

        self.generate_element(
            tk_loading_layer,
            {
                "element_id": 0,
                "element_alias": "LABEL_LOADING",
                "element_text": "ACTION",
                "relative": True,
                "element_pos": { 
                    "rel_x": 0.5, "rel_y": 0.5, 
                    "anchor": "center", "justify": "center" 
                }
            }
        )

        animation_thread = Thread(target=self.__animate_loading_layer, daemon=True)
        animation_thread.start()
        tk_loading_layer.place_forget()

    def __construct_tab_bar(self, element) -> None:
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

    def destroy_element_by_alias(self, alias: str) -> None:
        for element in self.__elements:
            if element.get_alias() == alias:
                element.get().get_tk_object().destroy() # destroy widget
                self.__elements.remove(element) # remove element object from elements list
                del element

    def generate_element(self, root_object: tk.Tk, element_scheme: dict) -> Element:
        self.__elements.append(Element(root_object, element_scheme))
        current_element = self.__elements[-1].get()

        if isinstance(current_element, UITabBar): # is last appended element a tab bar?
            self.__construct_tab_bar(current_element)

        if 'elements' in element_scheme:
            for sub_element in element_scheme['elements']:
                self.__elements.append(Element(current_element.get_tk_object(), sub_element))
                last_element = self.__elements[-1].get()

                if isinstance(last_element, UITabBar): # is last appended element a tab bar?
                    self.__construct_tab_bar(last_element)

        return current_element

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