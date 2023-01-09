import re

class StringsParser:

    def __init__(self, sample_buffer: bytes, window_object) -> None:
        self.__sample_buffer = sample_buffer
        self.__win_obj = window_object

        self.__loading_layer = self.__win_obj.get_element_by_alias('LOADING_LAYER').get()

        self.__strings = self.__win_obj.get_element_by_alias('TABLE_STRINGS').get()

        self.__strings.get_sheet_object().hide(canvas="x_scrollbar")
        self.__strings.get_sheet_object().show(canvas="y_scrollbar")
        self.__strings.set_column_widths([485, 80, 40, 60])

    def update(self, sample_buffer: bytes) -> None:
        self.__sample_buffer = sample_buffer

    def parse(self) -> None:
        self.__loading_layer.set_action('Collecting Strings')
        self.__loading_layer.set_sub_action("")

        # clear previous results
        self.__strings.clear()

        strings_data = list()

        strings_matches = re.finditer(
            b'[\x20-\x7e]{4,}', 
            self.__sample_buffer
        )

        for match in strings_matches:
            string_file_offset = match.regs[0][0]
            decoded_string = match.group().decode('ascii')
            string_size = len(decoded_string)
            string_type = 'ascii'

            strings_data.append([
                decoded_string, string_file_offset,
                string_size, string_type
            ])

        self.__strings.update_data(strings_data, False)
        self.__strings.set_column_widths([485, 80, 40, 60])
