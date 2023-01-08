import pygments.lexers as pyg_lexers
import pygments.styles as pyg_styles

import tkinter.scrolledtext as tkscrolled
import tkinter as tk

from chlorophyll import CodeView

class UITextBox:
    def __init__(self, root_object: tk.Tk, element_scheme: dict) -> None:
        self.__alias = element_scheme['element_alias']
        
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

    def set_text(self, text: str, monotone = False) -> None:
        self.__tk_object['state'] = 'normal'
        self.__tk_object.replace("1.0", tk.END, text)

        if monotone == True:
            self.__tk_object._set_lexer(pyg_lexers.CirruLexer)

        self.__tk_object['state'] = 'disabled'

    def get_tk_object(self) -> CodeView:
        return self.__tk_object

    def __del__(self):
        # print(f"[>] destroying UITextBox ({self.__alias}) [{hex(id(self))}]")
        pass
