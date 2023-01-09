import os, yara

from enum import IntEnum

class EYaraRuleType(IntEnum):
    RULE_UNKNOWN = -1,
    RULE_COMPILER = 0,
    RULE_PACKER = 1,
    RULE_INSTALLER = 2,
    RULE_CAPABILITIES = 3,
    RULE_PETOOLS = 4,
    RULE_DIE = 5

class YaraParser:

    def __init__(self, sample_buffer: bytes, window_object) -> None:
        self.__sample_buffer = sample_buffer
        self.__win_obj = window_object

        self.__loading_layer = self.__win_obj.get_element_by_alias('LOADING_LAYER').get()

        self.__compiler_info = self.__win_obj.get_element_by_alias('LABEL_COMPILER_INFO').get()
        self.__packer_info = self.__win_obj.get_element_by_alias('LABEL_PACKER_INFO').get()
        self.__installer_info = self.__win_obj.get_element_by_alias('LABEL_INSTALLER_INFO').get()

        self.__capabilities = self.__win_obj.get_element_by_alias('LISTBOX_CAPABILITIES').get()
        self.__signatures = self.__win_obj.get_element_by_alias('LISTBOX_SIGNATURES').get()

        self.__compiler_info.get_tk_object().config(text = "Compiler info: <unknown>")
        self.__packer_info.get_tk_object().config(text = "Packer info: <unknown>")
        self.__installer_info.get_tk_object().config(text = "Installer info: <unknown>")

    def __get_rule_type_by_filename(self, filename: str) -> EYaraRuleType:
        if 'compilers' in filename:
            return EYaraRuleType.RULE_COMPILER
        elif 'packers' in filename:
            return EYaraRuleType.RULE_PACKER
        elif 'installers' in filename:
            return EYaraRuleType.RULE_INSTALLER
        elif 'capabilities' in filename:
            return EYaraRuleType.RULE_CAPABILITIES
        elif 'petools' in filename:
            return EYaraRuleType.RULE_PETOOLS
        elif 'die' in filename:
            return EYaraRuleType.RULE_DIE

        return EYaraRuleType.RULE_UNKNOWN

    def __get_info_string_by_rule_type(self, yara_match, rule_type: EYaraRuleType) -> str:
        info = str()
        name = str()
        version = str()

        # name (if any)
        try: name = yara_match[rule_type]['name']
        except: name = "<unknown>"

        # version (if any)
        try: version = f"({yara_match[rule_type]['version']})"
        except: version = "(unknown version)"

        if rule_type == EYaraRuleType.RULE_COMPILER:
            info = f"Compiler info: {name} {version}"
        elif rule_type == EYaraRuleType.RULE_PACKER:
            info = f"Packer info: {name} {version}"
        elif rule_type == EYaraRuleType.RULE_INSTALLER:
            info = f"Installer info: {name} {version}"

        return info

    def __update_sample_info(self, yara_match) -> None:
        self.__loading_layer.set_action('Updating General Info')

        rule_type = list(yara_match.keys())[0]
    
        # update capabilities info
        if rule_type == EYaraRuleType.RULE_CAPABILITIES:
            if 'description' in yara_match[rule_type]:
                self.__capabilities.get_tk_object().insert(
                    0, yara_match[rule_type]['description']
                )
        elif rule_type == EYaraRuleType.RULE_PETOOLS:
            if 'description' in yara_match[rule_type]:
                self.__signatures.get_tk_object().insert(
                    0, f"PE Tools: {yara_match[rule_type]['description']}"
                )
        elif rule_type == EYaraRuleType.RULE_DIE:
            if 'description' in yara_match[rule_type]:
                self.__signatures.get_tk_object().insert(
                    0, f"DiE: {yara_match[rule_type]['description']}"
                )
        else: # update meta info
            info_string = self.__get_info_string_by_rule_type(yara_match, rule_type)
            self.__compiler_info.get_tk_object().config(text = info_string)

    def update(self, sample_buffer: bytes) -> None:
        self.__sample_buffer = sample_buffer

    def parse(self) -> None:
        # clear previous results
        self.__capabilities.get_tk_object().delete(
            0, self.__capabilities.get_tk_object().size()
        )

        self.__signatures.get_tk_object().delete(
            0, self.__signatures.get_tk_object().size()
        )

        yara_matches = list()
        yara_rules_dir = os.path.join('integrations', 'main', 'signatures')
        
        # perform yara scan (TODO: cache yara rules instead of reloading them every time)
        for filename in os.listdir(yara_rules_dir):

            if 'pe_sections' in filename: continue # ignore pe_sections db
            if 'comp_id' in filename: continue # ignore comp_id db

            yara_rule_type = self.__get_rule_type_by_filename(filename)
            filename = os.path.join(yara_rules_dir, filename)
            
            if os.path.isfile(filename):
                with open(filename, 'r', encoding='utf-8') as yara_rule:
                    try:
                        rule = yara.compile(source=yara_rule.read())
                        for match in rule.match(data=self.__sample_buffer):
                            yara_matches.append({yara_rule_type: match.meta} )

                    except yara.SyntaxError as ex:
                        print(f"[!] yara error, rule {filename} - {ex}")

        # update sample info based on yara matches
        for yara_match in yara_matches:
            self.__update_sample_info(yara_match)
