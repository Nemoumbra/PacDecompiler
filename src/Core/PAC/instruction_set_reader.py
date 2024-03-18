

from typing import Dict
from Core.PAC.pac_file import (
    PAC_instruction_template
)


class InstructionSetReader:
    def __init__(self):
        self.PAC_instruction_templates: Dict[int, PAC_instruction_template] = {}
        self.PAC_signature_to_name: Dict[int, str] = {}

    def read_instruction_set(self, file_path: str):
        with open(file_path, encoding="utf-8") as source:
            for line in source:
                words = line.strip().split(";")
                if len(words) < 4:
                    continue

                # signature;function_name;overlay_enum;address;
                # param_1_type;param_1_name;param_2_type;param_2_name...
                instr_info = words[0:4]
                args_info = words[4:]
                template = PAC_instruction_template(instr_info, args_info)

                self.PAC_instruction_templates[template.signature] = template
                self.PAC_signature_to_name[template.signature] = template.name
