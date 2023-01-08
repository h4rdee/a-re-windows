import tkinter as tk

class UILabel:
    def __init__(self, root_object: tk.Tk, element_scheme: dict) -> None:
        self.__alias = element_scheme['element_alias']

        self.__tk_object = tk.Label(
            root_object, text=element_scheme['element_text'],
            justify=tk.LEFT
        )
        
        if 'relative' in element_scheme and element_scheme['relative'] == True:
            self.__tk_object.place(
                relx = element_scheme['element_pos']['rel_x'],
                rely = element_scheme['element_pos']['rel_y'],
                anchor = element_scheme['element_pos']['anchor']
            )
            self.__tk_object.config(justify=element_scheme['element_pos']['justify'])
        else:
            self.__tk_object.place(
                x = element_scheme['element_pos']['x'],
                y = element_scheme['element_pos']['y']
            )
            
    def get_alias(self) -> str:
        return self.__alias

    def get_tk_object(self) -> tk.Label:
        return self.__tk_object

    def __del__(self):
        # print(f"[>] destroying UILabel ({self.__alias}) [{hex(id(self))}]")
        pass
