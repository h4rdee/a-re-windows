from gui.layout import Layout
from gui.window import Window

class GUI:
    def __init__(self, layout_path: str) -> None:
        self.__layout_scheme = Layout(layout_path).get_layout_scheme()
        self.__windows = list()

    def contstruct_window_by_alias(self, alias: str) -> Window:
        for window_scheme in self.__layout_scheme['windows']:
            if window_scheme['window_alias'] != alias:
                continue

            window_name = window_scheme['window_name']
            print(f'[>] creating window: "{window_name}"')
            self.__windows.append(Window(window_scheme))
            return self.__windows[-1]

    def get_window_by_alias(self, alias: str) -> Window:
        for window in self.__windows:
            if window.get_alias() == alias:
                return window
