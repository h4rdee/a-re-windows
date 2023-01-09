import pefile, hashlib, ppdeep

class HashesParser:

    def __init__(self, pe: pefile.PE, sample_buffer: bytes, window_object) -> None:
        self.__pe_object = pe
        self.__sample_buffer = sample_buffer
        self.__win_obj = window_object

        self.__loading_layer = self.__win_obj.get_element_by_alias('LOADING_LAYER').get()

        self.__hash_sha256 = self.__win_obj.get_element_by_alias('TEXTBOX_HASH_SHA256').get()
        self.__hash_sha1 = self.__win_obj.get_element_by_alias('TEXTBOX_HASH_SHA1').get()
        self.__hash_md5 = self.__win_obj.get_element_by_alias('TEXTBOX_HASH_MD5').get()
        self.__hash_imphash = self.__win_obj.get_element_by_alias('TEXTBOX_HASH_IMPHASH').get()
        self.__hash_rich = self.__win_obj.get_element_by_alias('TEXTBOX_HASH_RICH').get()
        self.__hash_ssdeep = self.__win_obj.get_element_by_alias('TEXTBOX_HASH_SSDEEP').get()

    def update(self, pe: pefile.PE, sample_buffer: bytes) -> None:
        self.__pe_object = pe
        self.__sample_buffer = sample_buffer

    def parse(self) -> None:
        self.__loading_layer.set_action('Updating Hashes')

        self.__loading_layer.set_sub_action('Calculating SHA256')
        self.__hash_sha256.set_text(hashlib.sha256(self.__sample_buffer).hexdigest(), True)

        self.__loading_layer.set_sub_action('Calculating SHA1')
        self.__hash_sha1.set_text(hashlib.sha1(self.__sample_buffer).hexdigest(), True)

        self.__loading_layer.set_sub_action('Calculating MD5')
        self.__hash_md5.set_text(hashlib.md5(self.__sample_buffer).hexdigest(), True)

        self.__loading_layer.set_sub_action('Calculating IMPHASH')
        self.__hash_imphash.set_text(self.__pe_object.get_imphash(), True)
        
        self.__loading_layer.set_sub_action('Calculating RICH Header Hash')
        self.__hash_rich.set_text(self.__pe_object.get_rich_header_hash(), True)
        
        # self.__loading_layer.set_sub_action('Calculating SSDEEP')
        # self.__hash_ssdeep.set_text(ppdeep.hash(self.__sample_buffer), True)
