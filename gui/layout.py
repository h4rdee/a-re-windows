import json

class Layout:
    def __init__(self, layout_path: str) -> None:
        try:
            with open(layout_path, 'r', encoding='utf-8') as layout_file:
                try:
                    self.__layout_json = json.load(layout_file)
                except json.JSONDecodeError as ex:
                    print(f"[!] failed to decode UI layout: {ex}")
                    exit(-2)
        except FileNotFoundError:
            print("[!] UI layout (layout.json) not found")
            exit(-1)

        print("[+] loaded layout.json")

    def get_layout_scheme(self) -> dict:
        return self.__layout_json
