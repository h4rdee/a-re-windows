import pefile, binascii

class OverlayParser:

    def __init__(self, pe: pefile.PE, window_object) -> None:
        self.__pe_object = pe
        self.__win_obj = window_object

        self.__loading_layer = self.__win_obj.get_element_by_alias('LOADING_LAYER').get()

        self.__overlay = self.__win_obj.get_element_by_alias('TABLE_OVERLAY_HEX').get()

        self.__overlay.get_sheet_object().hide(canvas="x_scrollbar")
        self.__overlay.get_sheet_object().show(canvas="y_scrollbar")
        self.__overlay.set_column_widths(
            [30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 180]
        )

    def update(self, pe: pefile.PE) -> None:
        self.__pe_object = pe

    def parse(self) -> None:
        self.__loading_layer.set_action('Parsing Overlay Data')

        # clear previous results
        self.__overlay.clear()

        overlay_data = self.__pe_object.get_overlay()
        result = list()

        if overlay_data:
            # found some overlay data, process it
            offset = 0
            for _ in range(0, len(overlay_data), 16):
                overlay_chunk = bytearray(overlay_data[offset : offset + 16])

                if len(overlay_chunk) != 16:
                    overlay_chunk.extend(b'\x00' * (16 - len(overlay_chunk)))

                hexed_chunk = binascii.hexlify(overlay_chunk, ' ').decode('ascii', 'ignore').split(' ')
                hexed_chunk.append(overlay_chunk.decode('utf-8', 'ignore').replace('\x00', '.').replace('\n', ''))

                result.append(hexed_chunk)
                offset += 16

        self.__overlay.update_data(result)
        self.__overlay.set_column_widths(
            [30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 180]
        )
        self.__overlay.get_sheet_object().enable_bindings("drag_select")
