import pygments.lexers as pyg_lexers
import pygments.styles as pyg_styles

import tkinter.scrolledtext as tkscrolled
import tkinter as tk

from chlorophyll import CodeView

class UITextBox:
    def __init__(self, root_object: tk.Tk, element_scheme: dict) -> None:
        self.__tk_object = CodeView(
            root_object, 
            lexer=pyg_lexers.CppLexer, 
            color_scheme="dracula",
            font=("Helvetica", 10)
        )

        self.__tk_object.insert(tk.END, element_scheme['element_text'])

        if element_scheme['element_readonly'] == True:
            self.__tk_object.config(state=tk.DISABLED)

        self.__tk_object.place(
            x = element_scheme['element_pos']['x'],
            y = element_scheme['element_pos']['y'],
            width = element_scheme['element_pos']['w'],
            height = element_scheme['element_pos']['h']
        )

    def get_tk_object(self) -> CodeView:
        return self.__tk_object
