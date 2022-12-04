import os

from ui import GUI

from integrations.integrations import Integrations

def main() -> None:
    layout_path = os.path.join(os.getcwd(), 'layout.json')
    gui = GUI(layout_path)
    main_window = gui.contstruct_window_by_alias('main')
    integrations = Integrations(main_window)
    integrations.setup_callbacks()
    main_window.get().mainloop()

if __name__ == '__main__':
    main()
