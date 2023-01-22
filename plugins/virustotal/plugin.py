import threading, hashlib, requests, json, os

class VirusTotal:

    def __init__(self, plugin_object) -> None:
        self.__plugin_object = plugin_object
        self.__window_object = plugin_object.get_window_object()
        self.__loading_layer = plugin_object.get_loading_layer()
        self.__plugin_settings = None

        self.__button_vt_analyze = self.__window_object.get_element_by_alias('BUTTON_VT_ANALYZE').get()
        self.__button_vt_analyze.get_tk_object().config(command=self.__vt_analyze_pressed)

        self.__table_vt_results = self.__window_object.get_element_by_alias('TABLE_VT_RESULTS').get()
        self.__table_vt_results.set_column_widths([366, 366])
        self.__table_vt_results.get_sheet_object().hide(canvas="x_scrollbar")
        self.__table_vt_results.get_sheet_object().show(canvas="y_scrollbar")

        self.__label_vt_result = self.__window_object.get_element_by_alias('LABEL_VT_RESULT').get()

        self.__load_settings()

    def __load_settings(self) -> None:
        settings_file_path = os.path.join(
            self.__plugin_object.get_plugin_dir(),
            'plugin_settings.json'
        )

        try:
            
            if os.path.isfile(settings_file_path):
                with open(settings_file_path, 'rb') as plugin_settings:
                    self.__plugin_settings = json.load(plugin_settings)

        except FileNotFoundError:
            print("[!] error occurred while parsing VirusTotal plugin settings: plugin_settings.json missing")
            return

    def __fetch_analysis(self, url):
        self.__loading_layer.set_sub_action(f"Sending request to VirusTotal")
        
        response = requests.get(
            url, headers = { "x-apikey": self.__plugin_settings['API_KEY'] }
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

        self.__table_vt_results.set_column_widths([366, 366])

    def __vt_analyze_pressed(self) -> None:
        if self.__plugin_object.get_binary_buffer() == None:
            print("[!] load binary first")
            return

        self.__loading_layer.set_action('Performing VirusTotal scan')

        dimensions = self.__loading_layer.get_dimensions()

        self.__loading_layer.get_tk_object().place(
            x = dimensions[0], y = dimensions[1],
            width = dimensions[2], height = dimensions[3]
        )
        
        url = f"https://www.virustotal.com/api/v3/files/{hashlib.sha256(self.__plugin_object.get_binary_buffer()).hexdigest()}"
        threading.Thread(target=self.__fetch_analysis, args=[url]).start()

def __init__(plugin_obj) -> None:
    plugin = VirusTotal(plugin_obj)
