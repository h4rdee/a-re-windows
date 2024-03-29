import tkinter as tk

from enum import IntEnum

from .elements.loading_layer import UILoadingLayer
from .elements.label import UILabel
from .elements.button import UIButton
from .elements.tab import UITab
from .elements.tab_bar import UITabBar
from .elements.textbox import UITextBox
from .elements.groupbox import UIGroupBox
from .elements.listbox import UIListBox
from .elements.table import UITable

class ElementID(IntEnum):
    UI_LOADING_LAYER = -1,
    UI_LABEL = 0,
    UI_BUTTON = 1,
    UI_TABBAR = 2,
    UI_TEXTBOX = 3,
    UI_GROUPBOX = 4,
    UI_LISTBOX = 5,
    UI_TAB = 6,
    UI_TABLE = 7

class Element:
    def __init__(self, root_object: tk.Tk, element_scheme: dict) -> None:
        self.__element = None
        self.__alias = element_scheme['element_alias']
        self.__element_id = element_scheme['element_id']

        if self.__element_id == ElementID.UI_LOADING_LAYER:
            self.__element = UILoadingLayer(root_object, element_scheme)
        elif self.__element_id == ElementID.UI_LABEL:
            self.__element = UILabel(root_object, element_scheme)
        elif self.__element_id == ElementID.UI_BUTTON:
            self.__element = UIButton(root_object, element_scheme)
        elif self.__element_id == ElementID.UI_TABBAR:
            self.__element = UITabBar(root_object, element_scheme)
        elif self.__element_id == ElementID.UI_TEXTBOX:
            self.__element = UITextBox(root_object, element_scheme)
        elif self.__element_id == ElementID.UI_GROUPBOX:
            self.__element = UIGroupBox(root_object, element_scheme)
        elif self.__element_id == ElementID.UI_LISTBOX:
            self.__element = UIListBox(root_object, element_scheme)
        elif self.__element_id == ElementID.UI_TAB:
            self.__element = UITab(root_object, element_scheme)
        elif self.__element_id == ElementID.UI_TABLE:
            self.__element = UITable(root_object, element_scheme)

    def get(self):
        return self.__element

    def get_alias(self) -> str:
        return self.__alias
