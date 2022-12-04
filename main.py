import os

from ui import GUI

def main():
    layout_path = os.path.join(os.getcwd(), 'layout.json')
    gui = GUI(layout_path)
    main_window = gui.contstruct_window_by_alias('main')
    main_window.get().mainloop()

if __name__ == '__main__':
    main()
