import requests
import hashlib
import threading

VT_KEY = "?"

class VirusTotalIntegration:
    def __init__(self) -> None:
        self.__elements = list()
        self.__window_object = None
        self.__binary_buffer = None
        self.__loading_layer = None

    def __vt_analyze_pressed(self) -> None:
        if self.__binary_buffer is None:
            print("[!] no binary to send over to virustotal")

            return

        self.__loading_layer.set_action('Performing VirusTotal scan')
        self.__loading_layer.set_sub_action('Building URL')

        self.__loading_layer = self.__window_object.get_element_by_alias('LOADING_LAYER').get()
        
        dimensions = self.__loading_layer.get_dimensions()
        self.__loading_layer.get_tk_object().place(
            x = dimensions[0], 
            y = dimensions[1],
            width = dimensions[2],
            height = dimensions[3]
        )
        
        url = "https://www.virustotal.com/api/v3/files/%s" % hashlib.sha256(self.__binary_buffer).hexdigest()

        self.__loading_layer.set_sub_action('Sending request to %s' % url)

        fetch_thread = threading.Thread(target=self.__fetch_analysis, args=[url])
        fetch_thread.start()

    def __fetch_analysis(self, url):
        response = requests.get(url, headers={ "x-apikey": VT_KEY })

        self.__on_analysis_response_arrived(response)

    def __on_analysis_response_arrived(self, response):
        if response.status_code == 200:
            self.__on_analysis_completed(response.json())

            self.__loading_layer.get_tk_object().place_forget()
        else:
            print("[!] failed to fetch analysis data (%d): %s" % (response.status_code, response.text))

            self.__loading_layer.get_tk_object().place_forget()

    def __on_analysis_completed(self, analysis) -> None:
        stats = analysis["data"]["attributes"]["last_analysis_stats"]
        results = analysis["data"]["attributes"]["last_analysis_results"]

        self.__tk_label_vt_result.get_tk_object()["text"] = "Score: Safe: %d, Malicious: %d, Suspicious: %d, Undetected: %d, Failed: %d, Total: %d" % (stats["harmless"], stats["malicious"], stats["suspicious"], stats["undetected"], stats["confirmed-timeout"] + stats["type-unsupported"] + stats["failure"] + stats["timeout"], sum(stats.values()))
        self.__tk_table_vt_results.update_data([["%s (%s)" % (result["engine_name"], result["engine_version"]), result["result"]] for result in results.values()])

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
                self.__tk_table_vt_results = element.get()
            elif element_alias == 'LABEL_VT_RESULT':
                self.__tk_label_vt_result = element.get()
            elif element_alias == 'LOADING_LAYER':
                self.__loading_layer = element.get()

        self.__tk_table_vt_results.set_column_widths([300, 300])

    def request_needed_elements(self) -> list:
        return [
            'BUTTON_VT_ANALYZE', 
            'TABLE_VT_RESULTS',
            'LABEL_VT_RESULT',
            'LOADING_LAYER'
        ]
