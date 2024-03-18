
from Core.PAC.pac_file import (
    PAC_file, PAC_instruction
)
from Utils.utils import (
    load_file_by_path, print_hex
)
from Core.PAC.pac_parser import (
    PAC_parser
)

from pathlib import Path
from typing import Dict, Set

from Core.decompiler.pac_decompiler import (
    PAC_Decompiler, DecompilerSettings
)

from Core.decompiler.decompiler_paths import *

from Core.decompiler.pac_vt_session import (
    PAC_VtSession, VTSettings, BytesCorrelator, InstructionsCorrelator, DataCorrelator
)

from Core.PAC.instruction_set_reader import (
    InstructionSetReader
)


def run_tests():
    print("run_tests() started!")
    instr_set_reader = InstructionSetReader()

    instr_set_reader.read_instruction_set(instructions_info_path)
    print("Instructions file loaded...")
    signature_to_name = instr_set_reader.PAC_signature_to_name

    pac_parser: PAC_parser = PAC_parser()
    pac_parser.setTemplates(instr_set_reader.PAC_instruction_templates)

    pac_file_path = input()

    pac_file = PAC_file()
    pac_file.name = pac_file_path[pac_file_path.rfind("\\") + 1:]
    pac_file.initialize_by_raw_data(load_file_by_path(pac_file_path))
    pac_parser.cmd_inxJmp_signature = 0x25002f00
    pac_parser.reset(pac_file)
    pac_parser.parse()
    print(f"PAC file {pac_file.name} parsed...")

    print("Starting tests...")
    print()

    decompiler: PAC_Decompiler = PAC_Decompiler()
    decompiler.setResources(signature_to_name)
    decompiler.reset(pac_file)
    settings = DecompilerSettings()
    settings.make_dot_file = True
    settings.SVG_path = input()

    settings.include_callbacks = False

    decompiler.decompile(settings)
    print("Callback destinations:")
    print_hex(list(decompiler.code.callback_destinations.values()))
    print()

    user_input = input("Issue a command!\n")
    while user_input != "":
        try:
            command_name, args_input = user_input.split(":")
            args = args_input.strip().split(", ")

            if command_name == "reachable":
                offsets = set(map(lambda n: int(n, 16), args))
                name = input("Name = ")
                print(decompiler.draw_reachable(offsets, name=name))
            elif command_name == "parents":
                offsets = set(map(lambda n: int(n, 16), args))
                name = input("Name = ")
                print(decompiler.draw_parents(offsets, name=name))
            else:
                pass
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print("Error", e)
        user_input = input("Issue a command!\n")

    print("Let's see what setGateInfo's arg[3] can be...")
    setGateInfo_signature = 0x2516bd00
    setGateInfo = pac_file.getInstructions(setGateInfo_signature)
    setGateInfo_values: Set[int] = set()
    for address, instruction in setGateInfo.items():
        value_type = instruction.ordered_PAC_params[3][0].type
        if value_type.startswith("0x1"):
            value = instruction.ordered_PAC_params[3][1]
            setGateInfo_values.add(value)
    print(", ".join([f"0x{value:X}" for value in setGateInfo_values]))

    # for signature, instructions in pac_file.instructions.items():
    #     for address, instruction in instructions.items():
    #         # let's skip the well-understood instructions
    #         # if signature in PAC_code.cm
    #         pass

    print()

    print("Tests end, exiting...")
    exit()


def analyze_PAC_variables(file: PAC_file):
    _0x4_var: Set[int] = set()
    _0x8_var: Set[int] = set()
    _0x20_var: Set[int] = set()
    _0x40_var: Set[int] = set()
    for location, instruction in file.ordered_instructions.items():
        for arg in instruction.ordered_PAC_params:
            arg_type = arg[0].type
            val = arg[1]
            if arg_type.startswith("0x4 "):
                _0x4_var.add(val)
            elif arg_type.startswith("0x8 "):
                _0x8_var.add(val)
            elif arg_type.startswith("0x20 "):
                _0x20_var.add(val)
            elif arg_type.startswith("0x40 "):
                _0x40_var.add(val)
    used_0x4 = sorted(_0x4_var)
    used_0x8 = sorted(_0x8_var)
    used_0x20 = sorted(_0x20_var)
    used_0x40 = sorted(_0x40_var)

    if used_0x4:
        max_index = used_0x4[-1]
        unused_0x4 = sorted(set(range(max_index + 1)).difference(_0x4_var))
        print(f"0x4 variables: max used index = {max_index}")
        print("Unused indexes:", unused_0x4)
    else:
        print("0x4 variables not used!")
    print()
    if used_0x8:
        max_index = used_0x8[-1]
        unused_0x8 = sorted(set(range(max_index + 1)).difference(_0x8_var))
        print(f"0x8 variables: max used index = {max_index}")
        print("Unused indexes:", unused_0x8)
    else:
        print("0x8 variables not used!")
    print()
    if used_0x20:
        max_index = used_0x20[-1]
        unused_0x20 = sorted(set(range(max_index + 1)).difference(_0x20_var))
        print(f"0x20 variables: max used index = {max_index}")
        print("Unused indexes:", unused_0x20)
    else:
        print("0x20 variables not used!")
    print()
    if used_0x40:
        max_index = used_0x40[-1]
        unused_0x40 = sorted(set(range(max_index + 1)).difference(_0x40_var))
        print(f"0x40 variables: max used index = {max_index}")
        print("Unused indexes:", unused_0x40)
    else:
        print("0x40 variables not used!")
    print()


def associate_pac_vars_and_instr(file: PAC_file):
    _0x4_vars: Dict[int, Dict[int, PAC_instruction]] = {}
    _0x8_vars: Dict[int, Dict[int, PAC_instruction]] = {}
    _0x20_vars: Dict[int, Dict[int, PAC_instruction]] = {}
    _0x40_vars: Dict[int, Dict[int, PAC_instruction]] = {}

    for location, instruction in file.ordered_instructions.items():
        used_variables = instruction.get_used_pac_vars()
        # after getting all variables we start putting them in the data structures
        for instr_0x4_var in sorted(used_variables.var_0x4):
            if instr_0x4_var not in _0x4_vars:
                _0x4_vars[instr_0x4_var] = {}
            _0x4_vars[instr_0x4_var][location] = instruction

        for instr_0x8_var in sorted(used_variables.var_0x8):
            if instr_0x8_var not in _0x8_vars:
                _0x8_vars[instr_0x8_var] = {}
            _0x8_vars[instr_0x8_var][location] = instruction

        for instr_0x20_var in sorted(used_variables.var_0x20):
            if instr_0x20_var not in _0x20_vars:
                _0x20_vars[instr_0x20_var] = {}
            _0x20_vars[instr_0x20_var][location] = instruction

        for instr_0x40_var in sorted(used_variables.var_0x40):
            if instr_0x40_var not in _0x40_vars:
                _0x40_vars[instr_0x40_var] = {}
            _0x40_vars[instr_0x40_var][location] = instruction
    return _0x4_vars, _0x8_vars, _0x20_vars, _0x40_vars


def decompile_pacs_in_directory(directory: Path, save_to: Path):
    instr_set_reader = InstructionSetReader()
    pac_parser = PAC_parser()
    instr_set_reader.read_instruction_set(str(instructions_info_path))
    pac_parser.setTemplates(instr_set_reader.PAC_instruction_templates)

    # pac_parser.cmd_inxJmp_signature = 0x25002D00  # P2
    pac_parser.cmd_inxJmp_signature = 0x25002f00  # P3

    pac_decompiler = PAC_Decompiler()
    pac_decompiler.setResources(instr_set_reader.PAC_signature_to_name)
    settings = DecompilerSettings()
    settings.SVG_path = str(save_to)
    settings.verbose_level = 2
    settings.include_callbacks = True

    files = directory.glob("*.pac")
    console_commands = []
    for path in files:
        if not path.is_file():
            continue
        try:
            file = PAC_file()
            full_path = directory / path.name
            file.initialize_by_raw_data(load_file_by_path(str(full_path)))
            file.name = path.name

            pac_parser.reset(file)
            pac_parser.parse()
            print(f"{path.name} parsed successfully!")

            pac_decompiler.reset(file)
            pac_decompiler.decompile(settings)
            console_commands.append(pac_decompiler.console_dot_command)

        except Exception as e:
            print(e)
    print()
    print("Paste this in the dotter file")
    print("\n".join(console_commands))
    pass


def version_tracking_tests():
    print("version_tracking_tests() started!")
    instr_set_reader = InstructionSetReader()
    instr_set_reader.read_instruction_set(instructions_info_path)
    print("Instructions file loaded...")
    signature_to_name = instr_set_reader.PAC_signature_to_name

    pac_parser: PAC_parser = PAC_parser()
    pac_parser.setTemplates(instr_set_reader.PAC_instruction_templates)

    def decompile(path):
        pac_file = PAC_file()
        pac_file.name = path[path.rfind("\\") + 1:]
        pac_file.initialize_by_raw_data(load_file_by_path(path))

        pac_parser.cmd_inxJmp_signature = 0x25002f00
        pac_parser.reset(pac_file)
        pac_parser.parse()
        print(f"PAC file {pac_file.name} parsed...")

        decompiler: PAC_Decompiler = PAC_Decompiler()
        decompiler.setResources(signature_to_name)
        decompiler.reset(pac_file)

        decomp_settings = DecompilerSettings()
        decomp_settings.make_dot_file = False
        decomp_settings.include_callbacks = False
        decomp_settings.SVG_path = r"k:\Shared_storage\Svgs\matches"

        print("Decompiling...")
        decompiler.decompile(decomp_settings)
        print("Decompiled!")
        return decompiler

    first_path = input()
    second_path = input()

    first = decompile(first_path)
    second = decompile(second_path)

    VT_session = PAC_VtSession()
    VT_session.reset(first, second)

    settings = VTSettings()
    settings.min_block_instr_count = 3
    settings.non_unique_matches = True

    correlator = InstructionsCorrelator()
    # correlator = BytesCorrelator()
    # correlator = DataCorrelator()
    correlator.setSettings(settings)

    matched = VT_session.correlate(correlator)
    if matched:
        print("Found matches!")
        dot_str = VT_session.make_dot_file_for_matches(matched, True)
        print(dot_str)
        dot_str = VT_session.make_dot_file_for_matches(matched, False)
        print(dot_str)
    else:
        print("No matches!")

    print("Completed!")

