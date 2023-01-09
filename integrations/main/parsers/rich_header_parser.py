import os, json, pefile

class RichHeaderParser:

    def __init__(self, pe: pefile.PE, window_object) -> None:
        self.__pe_object = pe
        self.__win_obj = window_object
        self.__comp_id_db = None

        self.__loading_layer = self.__win_obj.get_element_by_alias('LOADING_LAYER').get()

        self.__rich_header_info = self.__win_obj.get_element_by_alias('LISTBOX_RICH_HEADER_INFO').get()

    def __analyze_rich_comp_id(self, rich_field: int) -> str:
        if self.__comp_id_db == None:
            signatures_path = os.path.join('integrations', 'main', 'signatures')
            with open(os.path.join(signatures_path, 'comp_id.json'), 'r') as comp_id_db:
                self.__comp_id_db = json.load(comp_id_db)

        for comp_id in self.__comp_id_db["data"]:
            if int(comp_id['comp_id'], 16) == rich_field:
                return comp_id['description']

    def update(self, pe: pefile.PE) -> None:
        self.__pe_object = pe

    def parse(self) -> None:
        self.__loading_layer.set_action('Parsing PE RICH Header')

        # clear previous results
        self.__rich_header_info.clear()

        rich_header = self.__pe_object.parse_rich_header()
        if rich_header is None:
            return
        
        rich_fields = rich_header.get("values", None)
        if len(rich_fields) % 2 != 0:
            return

        rich_infos = list()
        compid = None

        for rich_field in rich_fields:
            if rich_fields.index(rich_field) % 2 == 0:
                compid = self.__analyze_rich_comp_id(rich_field)
            else:
                if compid:
                    self.__loading_layer.set_sub_action(compid)
                    rich_infos.append(f"{compid}; count = {rich_field}")
                    compid = None

        for rich_info in rich_infos:
            self.__rich_header_info.add_entry(rich_info)
