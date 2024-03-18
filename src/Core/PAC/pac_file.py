
from typing import (
    Set, NamedTuple, List, Dict, Any, Tuple, Union
)
from Utils.utils import (
    read_int_from_bytes, read_float_from_bytes, read_custom_int_from_bytes,
    unpack_int_from_bytes, binary_search, read_shift_jis_from_bytes
)

from Core.PAC.pac_utils import (
    read_PAC_string_argument, is_PAC_instruction
)

from Utils.frozenkeys_dict import FrozenKeysDict

from pathlib import Path


class Memory_entity:
    def __init__(self):
        self.memory_location: int = 0
        self.size: int = 0
        self.raw_data: bytes = b""

    def initialize_by_raw_data(self, raw: bytes):
        self.raw_data = raw
        self.size = len(raw)

    def __str__(self):  # unfinished
        return f"Memory entity: size = {self.size} bytes"


class Padding_bytes(Memory_entity):
    def __init__(self, word_length):
        Memory_entity.__init__(self)
        self.machine_word_length = word_length
        self.zeroes_only = True

    def initialize_by_raw_data(self, raw: bytes):
        Memory_entity.initialize_by_raw_data(self, raw)
        for byte in raw:
            if byte != 0:
                self.zeroes_only = False
                return

    def __str__(self):  # unfinished
        return f"Padding bytes: count = {self.size}, machine word length = {self.machine_word_length}"


class Patapon_file(Memory_entity):
    def __init__(self):
        Memory_entity.__init__(self)
        self.name: str = ""

    def __str__(self):
        return "Patapon file" + (f" ({self.name})" if self.name != "" else "") + f", size={self.size} bytes"


class PAC_instruction_param(NamedTuple):
    type: str
    name: str


class PAC_variable(NamedTuple):
    type: str
    value: int


class PAC_variables(NamedTuple):
    var_0x4: Set[int]
    var_0x8: Set[int]
    var_0x20: Set[int]
    var_0x40: Set[int]


class PAC_constants(NamedTuple):
    const_0x2: Set[int]
    const_0x10: Set[int]


class PAC_instruction_template:
    def __init__(self, instr_info: List[str], args_info: List[str]):
        # signature;function_name;overlay_enum;address;

        self.function_address: int = int(instr_info[3], 16)
        self.signature: int = int(instr_info[0], 16)
        self.name: str = instr_info[1]
        self.overlay: int = int(instr_info[2])

        self.instr_class = (self.signature >> 16) % 256
        self.instr_index = self.signature % 65536
        # param_1_type;param_1_name;param_2_type;param_2_name...

        # Let's make a list of PAC_instruction_param
        pairs = zip(args_info[0::2], args_info[1::2])
        self.PAC_params = [PAC_instruction_param(*i) for i in pairs]
        pass


class PAC_instruction(Memory_entity):

    def __init__(self, raw: bytes, offset: int, template: PAC_instruction_template):
        Memory_entity.__init__(self)

        self.function_address = template.function_address
        self.signature = template.signature
        self.instr_class = template.instr_class
        self.instr_index = template.instr_index
        self.name = template.name
        self.overlay = template.overlay
        self.cut_off = False

        self.PAC_params: FrozenKeysDict = FrozenKeysDict()
        params_dict: Dict[PAC_instruction_param, Any] = {}
        self.ordered_PAC_params: List[Tuple[PAC_instruction_param, Any]] = []

        original_offset = offset
        offset += 4  # skip the signature

        # OUTDATED COMMENT LINES AHEAD!
        # NB! Anything but uintX_t, uintX_t_T, uintXC_t_T, uint32_t_T, uint32_t_P string
        # COUNT, ENTITY_ID and EQUIP_ID should not be used for now!

        for index, param in enumerate(template.PAC_params):
            # wait, is "index" unused? Looks like it is...
            if param.type == "uintX_t":
                # skip padding if needed
                if offset % 4 != 0:
                    offset += 4 - (offset % 4)
                val = read_int_from_bytes(raw, offset, "little")
                params_dict[param] = val
                self.ordered_PAC_params.append((param, val))
                offset += 4
            elif param.type.startswith("uintX_t_T"):
                # skip padding if needed
                if offset % 4 != 0:
                    offset += 4 - (offset % 4)

                arg_type = raw[offset]
                offset += 4

                values = self.argument_switch_case(raw, offset, arg_type, 4, param)
                if values is None:
                    # it means we're done
                    offset -= 4
                    break

                undefined_param, val = values

                params_dict[undefined_param] = val
                self.ordered_PAC_params.append((undefined_param, val))  # replace with "values"?
                offset += 4
            elif param.type.startswith("uintXC_t_T"):
                sizeof = 4 - (offset % 4)

                arg_type = raw[offset]
                offset += sizeof

                values = self.argument_switch_case(raw, offset, arg_type, 4, param)
                if values is None:
                    raise RuntimeError("Cannot init PAC_instruction: param.type is uintXC_t_T, but values is None!")
                undefined_param, val = values

                params_dict[undefined_param] = val
                self.ordered_PAC_params.append((undefined_param, val))
                offset += 4
            elif param.type.startswith("uint32_t_T"):
                arg_type = raw[offset]
                offset += 4

                values = self.argument_switch_case(raw, offset, arg_type, 4, param)
                if values is None:
                    # it means we're done
                    offset -= 4
                    break
                undefined_param, val = values

                params_dict[undefined_param] = val
                self.ordered_PAC_params.append((undefined_param, val))  # replace with "values"?
                offset += 4
            elif param.type.startswith("uint16_t_T"):
                arg_type = raw[offset]
                offset += 2

                values = self.argument_switch_case(raw, offset, arg_type, 2, param)
                # so far in this scenario "values" can't be None, but I'll throw a check just in case
                if values is None:
                    raise RuntimeError("Cannot init PAC_instruction: sizeof == 2, but values is None!")
                undefined_param, val = values

                params_dict[undefined_param] = val
                self.ordered_PAC_params.append((undefined_param, val))  # replace with "values"?
                offset += 2
                pass
            elif param.type == "float":
                val = read_float_from_bytes(raw, offset)
                params_dict[param] = val
                offset += 4
            elif param.type == "string":
                val, length = read_PAC_string_argument(raw, offset)
                val = val.replace("\x00", "")
                params_dict[param] = val
                self.ordered_PAC_params.append((param, val))
                offset += length
            elif param.type.startswith("COUNT_"):
                res, new_offset = self.read_count_argument(raw, offset, param)
                for count_param, val in res:
                    params_dict[count_param] = val
                    self.ordered_PAC_params.append((count_param, val))
                    offset = new_offset
                if self.cut_off:
                    # we've reached the new instruction
                    break
                pass
            elif param.type == "uint32_t" or param.type == "uint32_t_P":
                val = read_int_from_bytes(raw, offset, "little")
                params_dict[param] = val
                self.ordered_PAC_params.append((param, val))
                offset += 4
                pass
            elif param.type.startswith("CONTINOUS_"):  # unfinished
                # TO DO: fix the typo in the file
                remains = len(raw) - offset
                integer_count = remains // 4
                for i in range(integer_count):
                    val = read_int_from_bytes(raw, offset, "little")
                    continuous_param = PAC_instruction_param(f"continuous_{i}", "Unknown")
                    params_dict[continuous_param] = val
                    offset += 4
                pass
            elif param.type == "ENTITY_ID":
                offset += 4
                val = read_int_from_bytes(raw, offset, "little")
                params_dict[param] = val
                self.ordered_PAC_params.append((param, val))
                offset += 4
                pass
            elif param.type == "EQUIP_ID":
                offset += 4
                val = read_int_from_bytes(raw, offset, "little")
                params_dict[param] = val
                self.ordered_PAC_params.append((param, val))
                offset += 4
                pass
            elif param.type == "KEYBIND_ID":
                val = read_int_from_bytes(raw, offset, "little")
                params_dict[param] = val
                self.ordered_PAC_params.append((param, val))
                offset += 4
                pass
            else:
                pass

        self.PAC_params.initialize_from_dict(params_dict)
        # We are done now, so let's initialize raw data
        self.initialize_by_raw_data(raw[original_offset:offset])
        pass

    def argument_switch_case(self, raw: bytes, offset: int, arg_type: int, sizeof: int, param: PAC_instruction_param):
        """
        This is a switch-case code for parsing uint_something_T arguments like 02 00 00 00 FF FF FF FF. \n
        None is returned <=> arg_type is broken and there is a valid PAC signature at offset - sizeof

            :param raw: bytes object
            :param offset: offset
            :param arg_type: 0x1, 0x2, 0x4, 0x10, etc.
            :param sizeof: number of bytes this argument takes
            :param param: info from instruction template
            :returns: PAC_instruction_param for the dict and the arg value or None if the operation was unsuccessful
        """
        undefined_param: PAC_instruction_param
        # Weird, only param.name is used here.

        if arg_type == 0x40:
            val = read_custom_int_from_bytes(raw, offset, sizeof, "little")
            undefined_param = PAC_instruction_param("0x40 variable", param.name)
        elif arg_type == 0x20:
            val = read_custom_int_from_bytes(raw, offset, sizeof, "little")
            undefined_param = PAC_instruction_param("0x20 variable", param.name)
        elif arg_type == 0x10:  # float
            if sizeof == 2:
                raise ValueError("argument_switch_case error: can't decode 2-byte float value!")
            val = read_float_from_bytes(raw, offset)
            undefined_param = PAC_instruction_param("float", param.name)
        elif arg_type == 0x8:
            val = read_custom_int_from_bytes(raw, offset, sizeof, "little")
            undefined_param = PAC_instruction_param("0x8 variable", param.name)
        elif arg_type == 0x4:
            val = read_custom_int_from_bytes(raw, offset, sizeof, "little")
            undefined_param = PAC_instruction_param("0x4 variable", param.name)
        elif arg_type == 0x2:
            val = read_custom_int_from_bytes(raw, offset, sizeof, "little")
            undefined_param = PAC_instruction_param("uint32_t", param.name)
        elif arg_type == 0x1:
            val = read_custom_int_from_bytes(raw, offset, sizeof, "little")
            undefined_param = PAC_instruction_param("0x1 value", param.name)
        else:
            # Let's check if the thing that we've just read is a valid signature
            if sizeof != 2 and is_PAC_instruction(raw, offset - sizeof):  # is it ok to put sizeof here?
                # Also maybe turn this check into a bit mask?
                # TO DO: properly implement a check here
                self.cut_off = True
                return None
            val = read_custom_int_from_bytes(raw, offset, sizeof, "little")
            undefined_param = PAC_instruction_param("Unknown", param.name)
        return undefined_param, val

    def read_count_argument(self, raw: bytes, offset: int, param: PAC_instruction_param):
        """
        :param raw: bytes object
        :param offset: offset
        :param param: info from instruction template
        :returns: a list of tuples in form (count_param, val) and the offset after the end of the count args range
        """
        # COUNT_uint32t_uint32tP
        count_info, args_info = param.type.split("_")[1:3]
        res: List[Tuple[PAC_instruction_param, int]] = []

        if count_info == "byte":
            count = raw[offset]

            # if 4th arg of getArgValuePtr is 4, it aligns PAC_PC
            offset += 4

            if args_info == "uint32t":
                for i in range(count):
                    arg_type = raw[offset]
                    offset += 4
                    values = self.argument_switch_case(raw, offset, arg_type, 4, param)
                    if values is None:
                        offset -= 4
                        break
                    undefined_param, val = values
                    count_param = PAC_instruction_param(f"count_{count_info} {undefined_param.type} {i}", param.name)
                    res.append((count_param, val))
                    offset += 4
            elif args_info == "uint32tP":
                for i in range(count):
                    val = read_int_from_bytes(raw, offset, "little")
                    count_param = PAC_instruction_param(f"count_{count_info}_{i}", "Unknown")
                    res.append((count_param, val))
                    offset += 4

        elif count_info == "uint32t":
            arg_type = raw[offset]
            if arg_type != 0x2 and arg_type != 0x1:
                raise RuntimeError(f"Cannot parse {param.type} argument at offset {offset:X}")
            offset += 4
            count = read_int_from_bytes(raw, offset, "little")
            offset += 4

            if args_info == "uint32t":
                for i in range(count):
                    arg_type = raw[offset]
                    offset += 4
                    values = self.argument_switch_case(raw, offset, arg_type, 4, param)
                    if values is None:
                        offset -= 4
                        break
                    undefined_param, val = values
                    count_param = PAC_instruction_param(f"count_{count_info} {undefined_param.type} {i}", param.name)
                    res.append((count_param, val))
                    offset += 4
            elif args_info == "uint32tP":
                for i in range(count):
                    val = read_int_from_bytes(raw, offset, "little")
                    count_param = PAC_instruction_param(f"count_{count_info}_{i}", "Unknown")
                    res.append((count_param, val))
                    offset += 4

        elif count_info == "uint32tP":
            count = read_int_from_bytes(raw, offset, "little")
            offset += 4

            if args_info == "uint32t":
                for i in range(count):
                    arg_type = raw[offset]
                    offset += 4
                    values = self.argument_switch_case(raw, offset, arg_type, 4, param)
                    if values is None:
                        offset -= 4
                        break
                    undefined_param, val = values
                    count_param = PAC_instruction_param(f"count_{count_info} {undefined_param.type} {i}", param.name)
                    res.append((count_param, val))
                    offset += 4
            elif args_info == "uint32tP":
                for i in range(count):
                    val = read_int_from_bytes(raw, offset, "little")
                    count_param = PAC_instruction_param(f"count_{count_info}_{i}", "Unknown")
                    res.append((count_param, val))
                    offset += 4

        return res, offset

    def __str__(self):  # unfinished
        ans = f"{hex(self.signature)} ({self.name})"
        return ans
        # for pac_param, value in self.ordered_PAC_params:
        #     pass

    def __repr__(self):
        return f"{hex(self.signature)} ({self.name})"

    def get_used_pac_vars(self) -> PAC_variables:
        args = self.ordered_PAC_params
        used = PAC_variables(set(), set(), set(), set())
        for arg in args:
            arg_type = arg[0].type
            if arg_type.startswith("0x4 "):
                used.var_0x4.add(arg[1])
            elif arg_type.startswith("0x8 "):
                used.var_0x8.add(arg[1])
            elif arg_type.startswith("0x20 "):
                used.var_0x20.add(arg[1])
            elif arg_type.startswith("0x40 "):
                used.var_0x40.add(arg[1])
        return used

    def get_used_0x1_values(self) -> List[int]:
        args = self.ordered_PAC_params
        ans = []
        for arg in args:
            arg_type = arg[0].type
            if arg_type.startswith("0x1"):
                ans.append(arg[1])
        return ans

    def get_used_4_byte_values(self) -> List[int]:
        args = self.ordered_PAC_params
        ans = []
        for arg in args:
            arg_type = arg[0].type
            if arg_type.startswith("uint32_t_P") or arg_type.startswith("uintX_t"):
                ans.append(arg[1])
        return ans

    def get_used_constants(self) -> PAC_constants:
        args = self.ordered_PAC_params
        used = PAC_constants(set(), set())
        for arg in args:
            arg_type = arg[0].type
            if arg_type == "uint32_t":
                used.const_0x2.add(arg[1])
            elif arg_type == "float":
                used.const_0x10.add(arg[1])
        return used

    def get_size(self) -> int:
        return self.size


class Unknown_PAC_instruction(Memory_entity):
    def __init__(self, raw: bytes):
        Memory_entity.__init__(self)
        self.signature = int.from_bytes(raw[0:4], "big")
        self.instr_class = (self.signature >> 16) % 256
        self.instr_index = self.signature % 65536
        self.initialize_by_raw_data(raw)
        pass

    def __str__(self):
        return f"{hex(self.signature)}"

    def __repr__(self):
        return f"{hex(self.signature)}"


class Left_out_PAC_arguments(Memory_entity):
    def __init__(self, raw: bytes, offset: int, name: str, signature: int, instr_offset: int):
        Memory_entity.__init__(self)
        self.raw_data = raw[offset:]
        self.size = len(self.raw_data)
        self.supposed_instruction = raw
        self.supposed_size = len(self.supposed_instruction)
        self.supposed_name = name
        self.supposed_signature = signature
        self.supposed_start = instr_offset


class PAC_message_table(Memory_entity):
    def __init__(self):
        Memory_entity.__init__(self)
        self.msg_count: int = 0

    def initialize_by_raw_data(self, raw: bytes):
        self.raw_data = raw
        self.size = len(raw)
        self.msg_count = self.size // 4


class Switch_case_table(Memory_entity):
    def __init__(self):
        Memory_entity.__init__(self)
        # self.number_of_branches = 0
        self.branches: List[int] = []

    def initialize_by_raw_data(self, raw: bytes):
        self.raw_data = raw
        self.size = len(raw)
        # self.number_of_branches = self.size // 4
        branches = [raw[4 * i: 4 * i + 4] for i in range(self.size // 4)]
        self.branches = list(map(unpack_int_from_bytes, branches))
        pass

    def __str__(self):
        return f"Switch-case table: size = {self.size} bytes, branches count = {len(self.branches)}"


class PAC_file(Patapon_file):
    def __init__(self):
        Patapon_file.__init__(self)
        self.instructions_count: int = 0
        self.unknown_instructions_count: int = 0
        self.cut_instructions_count: int = 0

        # Dictionary order is insertion order as of Python 3.7!
        self.cut_instructions: Dict[int, PAC_instruction] = {}
        self.raw_entities: Dict[int, Memory_entity] = {}
        self.padding_bytes: Dict[int, Padding_bytes] = {}
        self.switch_case_tables: Dict[int, Switch_case_table] = {}
        self.left_out_PAC_arguments: Dict[int, Left_out_PAC_arguments] = {}
        # self.contains_msg_table: bool = False
        self.msg_tables: Dict[int, PAC_message_table] = {}

        # self.temp_instructions: Dict[int, Dict[int, PAC_instruction]] = {}
        self.instructions: Dict[int, Dict[int, PAC_instruction]] = {}

        self.unknown_instructions: Dict[int, Dict[int, Unknown_PAC_instruction]] = {}
        # self.unknown_instructions: FrozenKeysDict = FrozenKeysDict.FrozenKeysDict()  # value type == ?

        self.instructions_offsets: List[int] = []
        self.ordered_instructions: Dict[int, PAC_instruction] = {}
        self.entities_offsets: List[int] = []
        self.entities: Dict[int, Union[Memory_entity, Padding_bytes, Switch_case_table, PAC_message_table,
                                       Left_out_PAC_arguments, Unknown_PAC_instruction, PAC_instruction]] = {}

    def get_entity_by_offset(self, offset: int) -> Tuple[int, Union[
            Memory_entity, Padding_bytes, Switch_case_table, PAC_message_table, Left_out_PAC_arguments,
            Unknown_PAC_instruction, PAC_instruction
        ]
    ]:
        """
        Returns the entity at given offset\n
        :param offset: the offset to get an entity from
        :return: actual starting offset and the entity
        """
        starting_offset = self.entities_offsets[binary_search(self.entities_offsets, offset)]
        return starting_offset, self.entities[starting_offset]

    def dump_data_to_directory(self, dir_path: str, attempt_shift_jis_decoding=False):
        # no checks regarding the directory
        raw_entity: Memory_entity
        base_path = Path(dir_path + "Untitled" if self.name == "" else dir_path + self.name)
        base_path.mkdir(exist_ok=True, parents=True)
        for location, raw_entity in self.raw_entities.items():
            with (base_path / str(location)).open("wb") as file:
                file.write(raw_entity.raw_data)
        if attempt_shift_jis_decoding and self.raw_entities:
            base_path /= "shift_jis"
            base_path.mkdir(exist_ok=True, parents=True)
            for location, raw_entity in self.raw_entities.items():
                try:
                    with (base_path / (str(location) + ".sjis")).open("wb") as file:
                        data = read_shift_jis_from_bytes(raw_entity.raw_data, 0, raw_entity.size)
                        file.write(data.encode("utf-8"))
                except Exception as e:
                    (base_path / (str(location) + ".sjis")).unlink(missing_ok=True)

    def getInstructions(self, signature: int) -> Dict[int, PAC_instruction]:
        if signature not in self.instructions:
            return {}
        return self.instructions[signature]  # can we not search for it again?


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
