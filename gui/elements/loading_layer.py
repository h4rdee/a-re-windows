import tkinter as tk

class UILoadingLayer:
    def __init__(self, root_object: tk.Tk, element_scheme: dict) -> None:
        self.__alias = element_scheme['element_alias']

        self.__tk_object = tk.Frame(root_object)

        self.__action = str()
        self.__sub_action = str()

        self.__dimensions = [
            element_scheme['element_pos']['x'],
            element_scheme['element_pos']['y'],
            element_scheme['element_pos']['w'],
            element_scheme['element_pos']['h']
        ]
        
        self.__tk_object.place(
            x = self.__dimensions[0],
            y = self.__dimensions[1],
            width = self.__dimensions[2],
            height = self.__dimensions[3]
        )

    def set_action(self, action: str) -> None:
        self.__action = action

    def set_sub_action(self, sub_action: str) -> None:
        self.__sub_action = sub_action

    def get_action(self) -> str:
        return self.__action
    
    def get_sub_action(self) -> str:
        return self.__sub_action

    def get_dimensions(self) -> list:
        return self.__dimensions

    def get_alias(self) -> str:
        return self.__alias

    def get_tk_object(self) -> tk.Label:
        return self.__tk_object

    def __del__(self):
        # print(f"[>] destroying UILoadingLayer ({self.__alias}) [{hex(id(self))}]")
        pass
