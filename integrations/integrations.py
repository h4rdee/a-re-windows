from .yara.yara import YaraIntegration

class Integrations:
    def __init__(self, window_object) -> None:
        self.__window_object = window_object
        self.__yara_integration = YaraIntegration()

    def setup_yara_integration(self) -> None:
        for alias in self.__yara_integration.request_needed_elements():
            element = self.__window_object.get_element_by_alias(alias)
            self.__yara_integration.register_element(element)
        self.__yara_integration.setup_callbacks()

    def setup_callbacks(self) -> None:
        self.setup_yara_integration()
