import os, sys

from ui import GUI
from integrations.integrations import Integrations

def main() -> None:
    layout_path = os.path.join(os.getcwd(), 'layout.json')
    gui = GUI(layout_path)

    main_window = gui.contstruct_window_by_alias('main')

    integrations = Integrations(main_window)
    integrations.setup()

    yara_integration = integrations.get_yara_integration()
    main_integration = integrations.get_main_integration()

    main_window.get().mainloop()

if __name__ == '__main__':
    python_version = sys.version_info
    if python_version < (3, 8, 10):
        print(f"[!] unsupported python version: {python_version} (required >=3.8.10)")
        exit(-3)
    else:
        main()
