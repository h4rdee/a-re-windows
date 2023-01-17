import requests
import hashlib
import threading

VT_KEY = "?"

class VirusTotalIntegration:
    def __init__(self) -> None:
        self.__window_object = None
        self.__binary_buffer = None
        self.__elements = list()

    def __vt_analyze_pressed(self) -> None:
        if self.__binary_buffer is None:
            print("[!] load binary first")
            return

        self.__loading_layer.set_action('Performing VirusTotal scan')

        dimensions = self.__loading_layer.get_dimensions()

        self.__loading_layer.get_tk_object().place(
            x = dimensions[0], y = dimensions[1],
            width = dimensions[2], height = dimensions[3]
        )
        
        url = f"https://www.virustotal.com/api/v3/files/{hashlib.sha256(self.__binary_buffer).hexdigest()}"
        threading.Thread(target=self.__fetch_analysis, args=[url]).start()

    def __fetch_analysis(self, url):
        self.__loading_layer.set_sub_action(f"Sending request")
        
        response = requests.get(
            url, headers = { "x-apikey": VT_KEY }
        )

        self.__on_analysis_response_received(response)

    def __on_analysis_response_received(self, response):
        if response.status_code == 200:
            self.__on_analysis_completed(response.json())
        else:
            print(f"[!] failed to fetch analysis data ({response.status_code}): {response.text}")

        self.__loading_layer.get_tk_object().place_forget()

    def __on_analysis_completed(self, analysis) -> None:
        # todo: harden it against any potential API changes by checking if this keys exist before using them
        stats = analysis["data"]["attributes"]["last_analysis_stats"]
        results = analysis["data"]["attributes"]["last_analysis_results"]

        failed_checks = stats["confirmed-timeout"] + stats["type-unsupported"] + stats["failure"] + stats["timeout"]

        self.__label_vt_result.get_tk_object().configure(
            text = f"Score: Safe: {stats['harmless']}; " \
                f"Malicious: {stats['malicious']}; Suspicious: {stats['suspicious']}; " \
                f"Undetected: {stats['undetected']}; Failed: {failed_checks}, Total: {sum(stats.values())}"
        )

        self.__table_vt_results.update_data(
            [
                ["%s (%s)" % (result["engine_name"], result["engine_version"]), result["result"]
            ] for result in results.values()]
        )

        self.__table_vt_results.set_column_widths([376, 376])

    def sample_loaded_event(self, binary_buffer: bytes) -> None:
        self.__binary_buffer = binary_buffer

    def set_window_object(self, window_object) -> None:
        self.__window_object = window_object

    def register_element(self, element) -> None:
        self.__elements.append(element)

    def setup(self) -> None:
        for element in self.__elements:
            tk_object = element.get().get_tk_object()
            element_alias = element.get_alias()

            if element_alias == 'BUTTON_VT_ANALYZE':
                tk_object.config(command=self.__vt_analyze_pressed)
            elif element_alias == 'TABLE_VT_RESULTS':
                self.__table_vt_results = element.get()
            elif element_alias == 'LABEL_VT_RESULT':
                self.__label_vt_result = element.get()
            elif element_alias == 'LOADING_LAYER':
                self.__loading_layer = element.get()

        self.__table_vt_results.set_column_widths([376, 376])

        self.__table_vt_results.get_sheet_object().hide(canvas="x_scrollbar")
        self.__table_vt_results.get_sheet_object().show(canvas="y_scrollbar")

    def request_needed_elements(self) -> list:
        return [
            'BUTTON_VT_ANALYZE', 
            'TABLE_VT_RESULTS',
            'LABEL_VT_RESULT',
            'LOADING_LAYER'
        ]
