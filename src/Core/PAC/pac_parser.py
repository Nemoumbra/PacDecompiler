
from typing import List, Tuple, Dict, Callable
from Utils.utils import (
    read_float_from_bytes, read_custom_int_from_bytes, read_int_from_bytes,
)
from Core.PAC.pac_utils import (
    is_PAC_instruction, read_PAC_string_argument, is_PAC_msg_table, is_left_out_PAC_args
)

from Core.PAC.pac_file import (
    PAC_instruction_param, PAC_instruction_template, PAC_file, PAC_message_table, Left_out_PAC_arguments,
    Memory_entity, PAC_instruction, Unknown_PAC_instruction, Padding_bytes, Switch_case_table
)

import struct


class PAC_instruction_parser:
    def __init__(self):
        self.data: bytes = b""
        self.cur_offset = 0
        self.cut_off = False

    def reset(self, data: bytes):
        self.data = data
        self.cur_offset = 0

    def goto(self, offset):
        self.cur_offset = offset

    def argument_switch_case(self, arg_type: int, sizeof: int, param: PAC_instruction_param):
        """
        This is a switch-case code for parsing uint_something_T arguments like 02 00 00 00 FF FF FF FF. \n
        None is returned <=> arg_type is broken and there is a valid PAC signature at offset - sizeof

            :param arg_type: 0x1, 0x2, 0x4, 0x10, etc.
            :param sizeof: number of bytes this argument takes
            :param param: info from instruction template
            :returns: PAC_instruction_param for the dict and the arg value or None if the operation was unsuccessful
        """

        undefined_param: PAC_instruction_param

        if arg_type == 0x10:
            # Float
            if sizeof == 2:
                raise ValueError("argument_switch_case error: can't decode 2-byte float value!")
            val = read_float_from_bytes(self.data, self.cur_offset)
            undefined_param = PAC_instruction_param("float", param.name)
            return val, undefined_param

        val = read_custom_int_from_bytes(self.data, self.cur_offset, sizeof, "little")

        if arg_type == 0x40:
            undefined_param = PAC_instruction_param("Float_global", param.name)
        elif arg_type == 0x20:
            undefined_param = PAC_instruction_param("Float_local", param.name)
        elif arg_type == 0x8:
            undefined_param = PAC_instruction_param("Int_global", param.name)
        elif arg_type == 0x4:
            undefined_param = PAC_instruction_param("Int_local", param.name)
        elif arg_type == 0x2:
            undefined_param = PAC_instruction_param("int", param.name)
        elif arg_type == 0x1:
            undefined_param = PAC_instruction_param("0x1 value", param.name)
        else:
            # Let's check if the thing that we've just read is a valid signature
            if sizeof != 2 and is_PAC_instruction(self.data, self.cur_offset - sizeof):  # is it ok to put sizeof here?
                # Also maybe turn this check into a bit mask?
                # TO DO: properly implement a check here
                self.cut_off = True
                return None
            undefined_param = PAC_instruction_param("Unknown", param.name)

        return undefined_param, val

    def read_byte_count_arg(self, info, param):
        count_info, args_info = info

        res = []
        count = self.data[self.cur_offset]

        # if 4th arg of getArgValuePtr is 4, it aligns PAC_PC
        self.cur_offset += 4

        if args_info == "uint32t":
            for i in range(count):
                arg_type = self.data[self.cur_offset]
                self.cur_offset += 4
                values = self.argument_switch_case(arg_type, 4, param)
                if values is None:
                    self.cur_offset -= 4
                    break
                undefined_param, val = values
                count_param = PAC_instruction_param(f"count_{count_info} {undefined_param.type} {i}", param.name)
                res.append((count_param, val))
                self.cur_offset += 4
        elif args_info == "uint32tP":
            for i in range(count):
                val = read_int_from_bytes(self.data, self.cur_offset, "little")
                count_param = PAC_instruction_param(f"count_{count_info}_{i}", "Unknown")
                res.append((count_param, val))
                self.cur_offset += 4

    def read_short_count_arg(self, info, param):
        pass

    def read_int_count_arg(self, info, param):
        pass

    def read_count_argument(self, param: PAC_instruction_param):
        """
            :param param: info from instruction template
            :returns: a list of tuples in form (count_param, val) and the offset after the end of the count args range
        """
        res: List[Tuple[PAC_instruction_param, int]] = []

        # COUNT_uint32t_uint32tP
        info = param.type.split("_")[1:3]
        count_info = info[0]

        if count_info == "byte":
            self.read_byte_count_arg(info, param)
        elif count_info == "uint32_t":
            self.read_int_count_arg(info, param)
        elif count_info == "uint32_t_P":
            pass

        pass

    def parse_string(self):
        val, length = read_PAC_string_argument(self.data, self.cur_offset)
        val = val.replace("\x00", "")
        return val, length

    def parse_float(self):
        val = read_float_from_bytes(self.data, self.cur_offset)
        return val, 4

    def parse_unaligned_int(self):
        # skip padding if needed
        padding_length = 0
        if self.cur_offset % 4 != 0:
            padding_length = 4 - (self.cur_offset % 4)
            self.cur_offset += padding_length
        val = read_int_from_bytes(self.data, self.cur_offset, "little")
        return val, padding_length + 4

    def parse_int(self):
        val = read_int_from_bytes(self.data, self.cur_offset, "little")
        return val, 4

    def parse_unaligned_composite(self, param: PAC_instruction_param):
        # skip padding if needed
        if self.cur_offset % 4 != 0:
            self.cur_offset += 4 - (self.cur_offset % 4)

        arg_type = self.data[self.cur_offset]
        self.cur_offset += 4

        values = self.argument_switch_case(arg_type, 4, param)
        if values is None:
            # it means we're done
            self.cur_offset -= 4
            # break

        return values

    def parse_compressed_composite(self, param: PAC_instruction_param):
        sizeof = 4 - (self.cur_offset % 4)

        arg_type = self.data[self.cur_offset]
        self.cur_offset += sizeof

        values = self.argument_switch_case(arg_type, 4, param)
        if values is None:
            raise RuntimeError("Cannot init PAC_instruction: param.type is uintXC_t_T, but values is None!")

        return values

    def parse_composite(self, param: PAC_instruction_param):
        arg_type = self.data[self.cur_offset]
        self.cur_offset += 4

        values = self.argument_switch_case(arg_type, 4, param)
        if values is None:
            # it means we're done
            self.cur_offset -= 4
            # break
        return values

    def parse_small_composite(self, param: PAC_instruction_param):
        arg_type = self.data[self.cur_offset]
        self.cur_offset += 2

        values = self.argument_switch_case(arg_type, 2, param)
        # so far in this scenario "values" can't be None, but I'll throw a check just in case
        if values is None:
            raise RuntimeError("Cannot init PAC_instruction: sizeof == 2, but values is None!")
        return values

    def parse_next(self, param: PAC_instruction_param):
        if param.type == "uintX_t":
            return self.parse_unaligned_int()
            pass
        elif param.type == "uintX_t_T":
            return self.parse_unaligned_composite(param)
            pass
        elif param.type == "uintXC_t_T":
            return self.parse_compressed_composite(param)
            pass
        elif param.type == "uint32_t_T":
            return self.parse_composite(param)
            pass
        elif param.type == "uint16_t_T":
            return self.parse_small_composite(param)
            pass
        elif param.type == "float":
            return self.parse_float()
            pass
        elif param.type == "string":
            return self.parse_string()
            pass
        elif param.type == "COUNT_":
            pass
        elif param.type == "uint32_t" or param.type == "uint32_t_P":
            return self.parse_int()
            pass
        elif param.type == "ENTITY_ID":
            return self.parse_int()
            pass
        elif param.type == "EQUIP_ID":
            return self.parse_int()
            pass
        elif param.type == "KEYBIND_ID":
            return self.parse_int()
            pass

    def parse(self, template: PAC_instruction_template):
        ans = []
        for index, param in enumerate(template.PAC_params):
            parsed = self.parse_next(param)


def defaultMayBeInstruction(signature: int) -> bool:
    if signature % 256 > 0x24:
        return False
    signature //= 256
    return signature % 256 != 0


class PAC_parser:
    def __init__(self):
        self.templates: Dict[int, PAC_instruction_template] = {}
        self.jump_table_next_to_switch = True
        self.cmd_inxJmp_signature = 0x0
        self.find_unknown_instructions = True
        self.PAC_signature_to_name: Dict[int, str] = {}  # maybe not needed...
        self.templates: Dict[int, PAC_instruction_template] = {}
        self.instruction_heuristic: Callable[[int], bool] = defaultMayBeInstruction

        self.file: PAC_file = PAC_file()
        self.cur_offset = 0
        self.last_offset = 0
        self.last_was_instruction = False
        self.cur_signature = 0x0

    def mayBeInstruction(self, signature: int):
        return self.instruction_heuristic(signature)

    def setTemplates(self, PAC_instruction_templates: Dict[int, PAC_instruction_template]):
        self.templates = PAC_instruction_templates

    def findNextInstruction(self) -> bool:
        """
        Tries to advance cur_offset to the next instruction or unknown instruction\n
        :return: True on success (if the file suffix contains instructions or unknown instructions)
        """
        percent = 0x25
        while True:
            # TO DO: implement alignment settings for better parsing
            # TO DO: maybe request that self.cur_offset < self.file.size - 4 and play with it to omit checking?
            while self.cur_offset < self.file.size and self.file.raw_data[self.cur_offset] != percent:
                self.cur_offset += 1
            # Now let's make a check...
            if self.cur_offset + 3 < self.file.size:
                # We have enough bytes
                possible_signature = struct.unpack_from(">i", self.file.raw_data, self.cur_offset)[0]

                # Let's do it the easy way:
                if possible_signature in self.templates:
                    return True

                # We don't know it so maybe it's an unknown instruction?
                if not self.find_unknown_instructions:
                    self.cur_offset += 1
                    continue

                # Here we use some sort of heuristic
                if self.mayBeInstruction(possible_signature):
                    return True

                self.cur_offset += 1
            else:
                # We don't have enough bytes
                return False

    def processMessageTable(self, raw: bytes):
        msg_table = PAC_message_table()
        msg_table.initialize_by_raw_data(raw)
        self.file.msg_tables[self.last_offset] = msg_table
        self.file.entities[self.last_offset] = msg_table

    def processLeftOutArgs(self, raw: bytes):
        instr_offset = self.file.entities_offsets[-1]
        instruction = self.file.ordered_instructions[instr_offset]
        args = Left_out_PAC_arguments(
            instruction.raw_data + raw,
            self.last_offset - instr_offset,
            instruction.name,
            instruction.signature,
            instr_offset
        )
        self.file.left_out_PAC_arguments[self.last_offset] = args
        self.file.entities[self.last_offset] = args

    def processMemoryEntity(self, raw: bytes):
        entity = Memory_entity()
        entity.initialize_by_raw_data(raw)
        self.file.raw_entities[self.last_offset] = entity
        self.file.entities[self.last_offset] = entity

    def processRawData(self):
        """
        Attempts to create a raw entity (either MSG table, left out PAC arguments or Memory entity) \n
        from the range [self.last_offset; self.cur_offset) and advances self.last_offset\n
        :return: Does not return anything
        """
        if self.cur_offset == self.last_offset:
            return

        raw = self.file.raw_data[self.last_offset:self.cur_offset]
        if is_PAC_msg_table(raw):
            self.processMessageTable(raw)
        elif self.last_was_instruction and is_left_out_PAC_args(raw):
            self.processLeftOutArgs(raw)
        else:
            self.processMemoryEntity(raw)

        self.file.entities_offsets.append(self.last_offset)
        self.last_offset = self.cur_offset
        self.last_was_instruction = False

    def processInstruction(self):
        # self.cur_signature must be set before calling this
        self.file.entities_offsets.append(self.cur_offset)
        template = self.templates[self.cur_signature]
        instruction = PAC_instruction(self.file.raw_data, self.cur_offset, template)

        if self.cur_signature not in self.file.instructions:
            self.file.instructions[self.cur_signature] = {}
        self.file.instructions[self.cur_signature][self.cur_offset] = instruction

        self.file.entities[self.cur_offset] = instruction
        self.file.ordered_instructions[self.cur_offset] = instruction
        self.file.instructions_offsets.append(self.cur_offset)

        if instruction.cut_off:
            self.file.cut_instructions[self.cur_offset] = instruction
            self.file.cut_instructions_count += 1

        self.cur_offset += instruction.size
        self.last_offset += instruction.size

        # Special cmd_inxJmp case:
        if self.jump_table_next_to_switch and self.cur_signature == self.cmd_inxJmp_signature:
            self.findNextInstruction()
            self.processAddressTable()

        if template.PAC_params and template.PAC_params[-1].type == "string":
            self.fixAlignment()

        self.last_was_instruction = True

    def processUnknownInstruction(self):
        # assumes self.last_offset == self.cur_offset
        self.cur_offset += 4
        res = self.findNextInstruction()

        # Unknown instruction will be from self.last_offset to self.cur_offset
        if not res:
            # No more instructions => the whole file suffix is an unknown instruction
            self.cur_offset = self.file.size

        raw = self.file.raw_data[self.last_offset:self.cur_offset]

        if self.cur_signature not in self.file.unknown_instructions:
            self.file.unknown_instructions[self.cur_signature] = {}

        unknown_instruction = Unknown_PAC_instruction(raw)
        self.file.unknown_instructions[self.cur_signature][self.last_offset] = unknown_instruction
        self.file.entities[self.last_offset] = unknown_instruction
        self.file.entities_offsets.append(self.last_offset)
        self.file.unknown_instructions_count += 1
        self.last_offset = self.cur_offset
        pass

    def fixAlignment(self):
        if self.cur_offset % 4 != 0:
            padding = Padding_bytes(4)
            padding_bytes_length = 4 - (self.cur_offset % 4)
            padding_raw = self.file.raw_data[self.cur_offset:self.cur_offset + padding_bytes_length]
            padding.initialize_by_raw_data(padding_raw)
            self.file.padding_bytes[self.cur_offset] = padding

            self.file.entities[self.cur_offset] = padding
            self.file.entities_offsets.append(self.cur_offset)
            self.cur_offset += padding_bytes_length
            self.last_offset += padding_bytes_length
            pass

    def processAddressTable(self):
        if self.cur_offset == self.last_offset:
            return
        raw = self.file.raw_data[self.last_offset:self.cur_offset]
        table = Switch_case_table()
        table.initialize_by_raw_data(raw)

        self.file.entities_offsets.append(self.last_offset)
        self.file.entities[self.last_offset] = table
        self.file.switch_case_tables[self.last_offset] = table
        self.last_offset = self.cur_offset

    def parse(self):
        if self.file.raw_data == b"":
            raise RuntimeError("PAC file raw data is empty!")

        while self.cur_offset < self.file.size:
            res = self.findNextInstruction()
            if res:
                self.processRawData()
                # now self.last_offset == self.cur_offset
                signature = struct.unpack_from(">i", self.file.raw_data, self.cur_offset)[0]
                self.cur_signature = signature

                # self.find_unknown_instructions == False => the else clause is never executed
                if signature in self.templates:
                    self.processInstruction()
                else:
                    self.processUnknownInstruction()
            else:
                # No more instructions => self.file.raw_data[self.last_offset:] is a raw entity
                self.cur_offset = self.file.size
                self.processRawData()
        pass

    def reset(self, file: PAC_file):
        self.file = file
        self.cur_offset = 0
        self.last_offset = 0
        self.last_was_instruction = False
        self.cur_signature = 0x0

