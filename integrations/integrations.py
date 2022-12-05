from .main.main import MainIntegration
from .yara.yara import YaraIntegration

class Integrations:
    def __init__(self, window_object) -> None:
        self.__window_object = window_object

        self.__yara_integration = YaraIntegration()

        self.__main_integration = MainIntegration(
            [self.__yara_integration]
        )

    def __setup_main_integration(self) -> None:
        for alias in self.__main_integration.request_needed_elements():
            element = self.__window_object.get_element_by_alias(alias)
            self.__main_integration.register_element(element)
        self.__main_integration.setup_callbacks()

    def __setup_yara_integration(self) -> None:
        for alias in self.__yara_integration.request_needed_elements():
            element = self.__window_object.get_element_by_alias(alias)
            self.__yara_integration.register_element(element)
        self.__yara_integration.setup_callbacks()

    def get_main_integration(self) -> MainIntegration:
        return self.__main_integration

    def get_yara_integration(self) -> YaraIntegration:
        return self.__yara_integration

    def setup_callbacks(self) -> None:
        self.__setup_main_integration()
        self.__setup_yara_integration()
