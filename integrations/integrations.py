from .main.main import MainIntegration
from .yara.yara import YaraIntegration
from .virustotal.virustotal import VirusTotalIntegration

class Integrations:
    def __init__(self, window_object) -> None:
        self.__window_object = window_object

        self.__yara_integration = YaraIntegration()
        self.__virustotal_integration = VirusTotalIntegration()
        self.__main_integration = MainIntegration([self.__yara_integration, self.__virustotal_integration])

        self.__yara_integration.set_window_object(window_object)
        self.__virustotal_integration.set_window_object(window_object)
        self.__main_integration.set_window_object(window_object)

    def __setup_main_integration(self) -> None:
        for alias in self.__main_integration.request_needed_elements():
            element = self.__window_object.get_element_by_alias(alias)
            self.__main_integration.register_element(element)
        self.__main_integration.setup()

    def __setup_yara_integration(self) -> None:
        for alias in self.__yara_integration.request_needed_elements():
            element = self.__window_object.get_element_by_alias(alias)
            self.__yara_integration.register_element(element)
        self.__yara_integration.setup()

    def __setup_virustotal_integration(self) -> None:
        for alias in self.__virustotal_integration.request_needed_elements():
            element = self.__window_object.get_element_by_alias(alias)
            self.__virustotal_integration.register_element(element)
        
        self.__virustotal_integration.setup()

    def get_main_integration(self) -> MainIntegration:
        return self.__main_integration

    def get_yara_integration(self) -> YaraIntegration:
        return self.__yara_integration

    def get_virustotal_integration(self) -> VirusTotalIntegration:
        return self.__virustotal_integration

    def setup(self) -> None:
        self.__setup_main_integration()
        self.__setup_yara_integration()
        self.__setup_virustotal_integration()
