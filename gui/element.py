import tkinter as tk

from enum import IntEnum

from .elements.label import UILabel
from .elements.button import UIButton
from .elements.tab_bar import UITabBar
from .elements.textbox import UITextBox

class ElementID(IntEnum):
    UI_LABEL = 0,
    UI_BUTTON = 1,
    UI_TABBAR = 2,
    UI_TEXTBOX = 3

class Element:
    def __init__(self, root_object: tk.Tk, element_scheme: dict) -> None:
        self.__element = None
        self.__alias = element_scheme['element_alias']

        if element_scheme['element_id'] == ElementID.UI_LABEL:
            self.__element = UILabel(root_object, element_scheme)
        elif element_scheme['element_id'] == ElementID.UI_BUTTON:
            self.__element = UIButton(root_object, element_scheme)
        elif element_scheme['element_id'] == ElementID.UI_TABBAR:
            self.__element = UITabBar(root_object, element_scheme)
        elif element_scheme['element_id'] == ElementID.UI_TEXTBOX:
            self.__element = UITextBox(root_object, element_scheme)

    def get(self):
        return self.__element

    def get_alias(self) -> str:
        return self.__alias
