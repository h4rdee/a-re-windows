import pefile, lief

class PEParser:

    def __init__(self, sample_buffer: bytes, pe: pefile.PE, window_object) -> None:
        lief.logging.disable()

        self.__pe_object = pe
        self.__win_obj = window_object
        self.__sample_buffer = sample_buffer

        self.__pe_checksum = None
        self.__lief_object = None

        self.__loading_layer = self.__win_obj.get_element_by_alias('LOADING_LAYER').get()

        self.__arch_info = self.__win_obj.get_element_by_alias('LABEL_ARCHITECTURE_INFO').get()
        self.__subsystem_info = self.__win_obj.get_element_by_alias('LABEL_SUBSYSTEM_INFO').get()
        self.__checksum_info = self.__win_obj.get_element_by_alias('LABEL_CHECKSUM_INFO').get()
        self.__signature_info = self.__win_obj.get_element_by_alias('LABEL_SIGNATURE_INFO').get()
        self.__format_info = self.__win_obj.get_element_by_alias('LABEL_FORMAT_INFO').get()
        self.__imagebase_info = self.__win_obj.get_element_by_alias('LABEL_IMAGEBASE_INFO').get()
        self.__entrypoint_info = self.__win_obj.get_element_by_alias('LABEL_EP_INFO').get()

        self.__arch_info.get_tk_object().config(text = "Architecture: <unknown>")
        self.__subsystem_info.get_tk_object().config(text = "Subsystem: <unknown>")
        self.__checksum_info.get_tk_object().config(text = "Checksum: <unknown>")
        self.__signature_info.get_tk_object().config(text = "Signature: <unknown>")
        self.__format_info.get_tk_object().config(text = "Format: <unknown>")
        self.__imagebase_info.get_tk_object().config(text = "ImageBase: <unknown>")
        self.__entrypoint_info.get_tk_object().config(text = "EP: <unknown>")

    def update(self, pe: pefile.PE, sample_buffer: bytes) -> None:
        self.__pe_object = pe
        self.__sample_buffer = sample_buffer
        self.__lief_object = lief.parse(raw = self.__sample_buffer)
        self.__pe_checksum = self.__pe_object.generate_checksum()

    def parse(self) -> None:
        self.__loading_layer.set_action('Parsing PE structure')

        checksum = self.__pe_object.OPTIONAL_HEADER.CheckSum
        signature = self.__lief_object.verify_signature()

        self.__arch_info.get_tk_object().config(
            text = f"Architecture: {pefile.MACHINE_TYPE[self.__pe_object.FILE_HEADER.Machine]}"
        )

        self.__subsystem_info.get_tk_object().config(
            text = f"Subsystem: {pefile.SUBSYSTEM_TYPE[self.__pe_object.OPTIONAL_HEADER.Subsystem]}"
        )

        if checksum != self.__pe_checksum:
            self.__checksum_info.get_tk_object().config(
                text = f"Checksum: {hex(checksum)}; should be - {hex(self.__pe_checksum)} [!]"
            )
        else:
            self.__checksum_info.get_tk_object().config(
                text = f"Checksum: {hex(checksum)}; verified [+]"
            )

        if signature == lief.PE.Signature.VERIFICATION_FLAGS.OK:
            self.__signature_info.get_tk_object().config(
                text = f"Signature: verified [+]"
            )
        elif signature == lief.PE.Signature.VERIFICATION_FLAGS.NO_SIGNATURE:
            self.__signature_info.get_tk_object().config(
                text = f"Signature: not signed [-]"
            )
        else:
            self.__signature_info.get_tk_object().config(
                text = f"Signature: invalid [!]"
            )

        if self.__pe_object.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE:
            self.__format_info.get_tk_object().config(text = "Format: PE32")
            
        elif self.__pe_object.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
            self.__format_info.get_tk_object().config(text = "Format: PE32+")

        try:
            self.__imagebase_info.get_tk_object().config(
                text = f"ImageBase: {hex(self.__pe_object.OPTIONAL_HEADER.ImageBase)}"
            )
        except AttributeError:
            pass

        try:
            self.__entrypoint_info.get_tk_object().config(
                text = f"EP: {hex(self.__pe_object.OPTIONAL_HEADER.AddressOfEntryPoint)}"
            )
        except AttributeError:
            pass
