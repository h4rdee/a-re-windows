import json, os

from importlib.machinery import SourceFileLoader

class Plugin:

    def __init__(self, window_object, loading_layer, plugin_dir) -> None:
        self.__window_object = window_object
        self.__loading_layer = loading_layer
        self.__plugin_dir = plugin_dir
        self.__plugin_data = None
        self.__parent_tab = None
        self.__binary_buffer = None

        try:
            filename = os.path.join(self.__plugin_dir, 'plugin_data.json')
            
            if os.path.isfile(filename):
                with open(filename, 'rb') as plugin_data:
                    self.__plugin_data = json.load(plugin_data)

        except FileNotFoundError:
            print("[!] error occurred while initializing plugin: plugin_data.json is missing")
            return

    def set_parent_tab(self, parent_tab) -> None:
        self.__parent_tab = parent_tab

    def get_parent_tab(self):
        return self.__parent_tab

    def get_window_object(self):
        return self.__window_object

    def get_loading_layer(self):
        return self.__loading_layer

    def get_binary_buffer(self) -> bytes:
        return self.__binary_buffer

    def get_plugin_dir(self):
        return self.__plugin_dir
        
    def get_plugin_data_field(self, field: str) -> str:
        if self.__plugin_data:
            if field in self.__plugin_data:
                return self.__plugin_data[field]
            else:
                return 'unknown'

    def sample_loaded_event(self, binary_buffer: bytes) -> None:
        self.__binary_buffer = binary_buffer

    def load(self) -> None:
        try:
            plugin_module = os.path.join(self.__plugin_dir, 'plugin.py')

            plugin = SourceFileLoader(
                os.path.basename(self.__plugin_dir), 
                plugin_module
            ).load_module()

            plugin.__init__(self)

        except Exception as ex:
            print(f'[-] failed to load {self.get_plugin_data_field("plugin_name")} plugin: {ex}\n')

class PluginsIntegration:

    def __init__(self) -> None:
        self.__window_object = None
        self.__loading_layer = None
        self.__tab_bar_plugins = None

        self.__elements = list()
        self.__plugins = list()

    def __setup_plugins(self) -> None:
        subfolders = [ f.path for f in os.scandir(os.path.join(os.getcwd(), "plugins")) if f.is_dir() ]

        for folder in subfolders:

            plugin = Plugin(
                self.__window_object,
                self.__loading_layer,
                folder
            )

            parent_tab = self.__window_object.generate_element(
                self.__tab_bar_plugins.get_tk_object(),
                {
                    "element_id": 6,
                    "element_text": plugin.get_plugin_data_field("plugin_name"),
                    "element_alias": f"TAB_{os.path.basename(folder).upper()}",
                    "element_state": False,
                    "elements": plugin.get_plugin_data_field('layout')['elements']
                }
            )

            plugin.set_parent_tab(parent_tab)
            plugin.load()

            self.__plugins.append(plugin)

    def sample_loaded_event(self, binary_buffer: bytes) -> None:
        for plugin in self.__plugins:
            plugin.sample_loaded_event(binary_buffer)

    def set_window_object(self, window_object) -> None:
        self.__window_object = window_object

    def register_element(self, element) -> None:
        self.__elements.append(element)

    def setup(self) -> None:
        for element in self.__elements:
            tk_object = element.get().get_tk_object()
            element_alias = element.get_alias()

            if element_alias == 'LOADING_LAYER':
                self.__loading_layer = element.get()
            elif element_alias == 'TAB_BAR_PLUGINS':
                self.__tab_bar_plugins = element.get()
        
        self.__setup_plugins()

    def request_needed_elements(self) -> list:
        return [
            'LOADING_LAYER',
            'TAB_BAR_PLUGINS'
        ]
