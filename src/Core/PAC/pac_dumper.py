
from typing import NamedTuple, TextIO
from Core.PAC.pac_file import (
    PAC_file, Memory_entity, PAC_instruction, PAC_message_table, Padding_bytes, Unknown_PAC_instruction,
    Switch_case_table, Left_out_PAC_arguments
)
from Utils.utils import (
    read_shift_jis_from_bytes
)
from pathlib import Path


class PAC_DisasmSettings(NamedTuple):
    omit_arg_names: bool = False
    skip_padding_bytes: bool = False
    decode_shift_jis: bool = True
    dump_failed_decodings: bool = False


class PAC_dumper:
    def __init__(self):
        self.file: PAC_file = PAC_file()
        self.settings: PAC_DisasmSettings = PAC_DisasmSettings()

    def reset(self, file: PAC_file, settings: PAC_DisasmSettings):
        self.file = file
        self.settings = settings

    def dump_memory_entity(self, text_file: TextIO, memory_entity: Memory_entity) -> bool:
        text_file.write(f"Memory entity: size = {memory_entity.size} bytes")
        if self.settings.decode_shift_jis:
            try:
                shift_jis_data = read_shift_jis_from_bytes(memory_entity.raw_data, 0, memory_entity.size)
                text_file.write(f", shift-jis = ({shift_jis_data})")
            except UnicodeDecodeError:
                text_file.write(f", hex = ({memory_entity.raw_data.hex(' ')})")
                return True
            return False

        # Let's just dump the hex values then
        text_file.write(f", hex = ({memory_entity.raw_data.hex(' ')})")
        return True

    def dump_PAC_instruction(self, text_file: TextIO, instruction: PAC_instruction):
        text_file.write(f"{instruction.signature:X}:{instruction.name}(")
        args_count = len(instruction.ordered_PAC_params)
        if args_count > 0:
            for param, value in instruction.ordered_PAC_params[0:-1]:
                if not self.settings.omit_arg_names:
                    text_file.write(f"{{{param.type}; {param.name}}}=")
                else:
                    # 0xX variable or uint32_t
                    if param.type == "uint32_t":
                        text_file.write("2:")
                    elif param.type.startswith("0x1"):
                        text_file.write("1:")
                    elif param.type.startswith("0x"):
                        text_file.write(param.type[2:4].strip() + ":")

                    pass
                if isinstance(value, int):
                    text_file.write(f"{value:X}, ")
                elif isinstance(value, str):
                    text_file.write("\"" + value.replace("\x00", "") + "\", ")
                else:
                    text_file.write(f"{value}, ")

            # Now the last argument:
            param, value = instruction.ordered_PAC_params[-1]
            if not self.settings.omit_arg_names:
                text_file.write(f"{{{param.type}; {param.name}}}=")
            else:
                # 0xX variable or uint32_t[_P]
                if param.type == "uint32_t":
                    text_file.write("2:")
                elif param.type.startswith("0x1"):
                    text_file.write("1:")
                elif param.type.startswith("0x"):
                    text_file.write(param.type[2:4].strip() + ":")
            if isinstance(value, int):
                text_file.write(f"{value:X}")
            elif isinstance(value, str):
                text_file.write("\"" + value.replace("\x00", "") + "\"")
            else:
                text_file.write(f"{value}")
        text_file.write(")")
        if instruction.cut_off:
            text_file.write(" [Warning, instruction unexpectedly ends!]")

    @staticmethod
    def dump_PAC_message_table(text_file: TextIO, message_table: PAC_message_table):
        text_file.write(
            f"Message table: size = {message_table.size} bytes, message count = {message_table.msg_count}"
        )

    @staticmethod
    def dump_padding_bytes(text_file: TextIO, padding_bytes: Padding_bytes):
        text_file.write(
            f"Padding bytes: count = {padding_bytes.size}, all zeroes = {padding_bytes.zeroes_only}, "
            f"machine word length = {padding_bytes.machine_word_length}"
        )

    @staticmethod
    def dump_unknown_PAC_instruction(text_file: TextIO, unknown_instruction: Unknown_PAC_instruction):
        text_file.write(
            f"{unknown_instruction.signature:X}(Unknown instruction): size = {unknown_instruction.size}"
        )

    @staticmethod
    def dump_switch_case_table(text_file: TextIO, switch_case_table: Switch_case_table):
        text_file.write(
            f"Switch-case table: size = {switch_case_table.size} bytes, "
            f"branches count = {len(switch_case_table.branches)}, addresses: ("
        )
        for branch in switch_case_table.branches[0:-1]:
            text_file.write(f"{branch:X}, ")
        text_file.write(f"{switch_case_table.branches[-1]:X})")

    @staticmethod
    def dump_left_out_PAC_args(text_file: TextIO, left_out_PAC_args: Left_out_PAC_arguments):
        text_file.write(
            f"Potential left out PAC args: size = {left_out_PAC_args.size} bytes, "
            f"supposed full size of the instruction = {left_out_PAC_args.supposed_size}"
        )

    def disassemble_to_file(self, where_to: Path):
        with open(where_to, "w", encoding="utf-8") as output:
            offsets_to_dump = []
            for file_offset in self.file.entities_offsets:
                hex_offset = f"{file_offset:08X}  "

                output.write(hex_offset)
                entity = self.file.entities[file_offset]
                entity_type = type(entity)
                if entity_type is Memory_entity:
                    # this variable can be removed
                    decoding_failed = self.dump_memory_entity(output, entity)
                    if decoding_failed:
                        print(f"Failed to decode shift-jis at {file_offset:X}"
                              f" (it will be dumped to file {file_offset:X}.bytes)")
                        offsets_to_dump.append(file_offset)
                elif entity_type is PAC_instruction:
                    self.dump_PAC_instruction(output, entity)
                elif entity_type is Unknown_PAC_instruction:
                    self.dump_unknown_PAC_instruction(output, entity)
                elif entity_type is Padding_bytes and not self.settings.skip_padding_bytes:
                    self.dump_padding_bytes(output, entity)
                elif entity_type is PAC_message_table:
                    self.dump_PAC_message_table(output, entity)
                elif entity_type is Switch_case_table:
                    self.dump_switch_case_table(output, entity)
                elif entity_type is Left_out_PAC_arguments:
                    self.dump_left_out_PAC_args(output, entity)
                output.write("\n")

            # Now we only need to dump the bad memory entities
            if not self.settings.dump_failed_decodings:
                return

            # where_to == directory / "azito.txt"
            new_directory = where_to.with_suffix("")
            if offsets_to_dump:
                # where_to.stem == path.name == azito
                new_directory.mkdir(exist_ok=True, parents=True)  # directory / "azito" /

            for offset in offsets_to_dump:
                with (new_directory / hex(offset)[2:]).with_suffix(".bytes").open("wb") as raw_file:
                    try:
                        raw_file.write(self.file.entities[offset].raw_data)
                    except Exception as e:
                        print(f"Unable to dump Memory entity at offset {offset} to file! Exception:", e)
