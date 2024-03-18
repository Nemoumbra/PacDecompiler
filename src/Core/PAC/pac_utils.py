
from typing import Tuple
from collections import Counter

from Utils.utils import (
    read_int_from_bytes, read_shift_jis_from_bytes
)


def is_PAC_msg_table(data: bytes) -> bool:
    if len(data) % 4 != 0:
        return False
    i = 0
    offset = 0
    while offset < len(data):
        if i != read_int_from_bytes(data, offset, "little"):
            return False
        i += 1
        offset += 4
    return True


def analyze_instruction_set(file_path: str):
    stats = Counter()
    print(file_path[file_path.rfind("\\") + 1:])
    with open(file_path, encoding="utf-8") as source:
        for line in source:
            words = line.strip().split(";")
            # A;B;C;D;raw_size(hex);function_name;extended_name;function_desc;param_amount;address;
            # param_1_type;param_1_name;param_2_type;param_2_name...
            arg_types_info = words[10::2]
            for arg_type in arg_types_info:
                if arg_type.startswith("uint32_t_T"):
                    stats["uint32_t_T"] += 1
                elif arg_type.startswith("uint16_t_T"):
                    stats["uint16_t_T"] += 1
                elif arg_type == "uint32_t_P":
                    stats["uint32_t_P"] += 1
                elif arg_type.startswith("uintX_t_T"):
                    stats["uintX_t_T"] += 1
                elif arg_type.startswith("uintXC_t_T"):
                    stats["uintXC_t_T"] += 1
                elif arg_type.startswith("COUNT_"):
                    # I don't want to implement this now
                    stats["COUNT"] += 1
                elif arg_type.startswith("CONTINOUS_"):
                    stats["CONTINOUS"] += 1
                elif arg_type == "uintX_t":
                    stats["uintX_t"] += 1
                elif arg_type == "string":
                    stats["string"] += 1
                else:
                    print(f"Unknown type {arg_type}")
                    stats[arg_type] += 1

    return stats


def read_PAC_string_argument(data: bytes, offset: int) -> Tuple[str, int]:
    original_offset = offset
    while data[offset] != 0:
        offset += 1
    length = offset - original_offset + 1
    return read_shift_jis_from_bytes(data, original_offset, length), length


def is_PAC_instruction(data: bytes, offset: int) -> bool:
    return data[offset] == 0x25 and data[offset + 3] <= 0x23


def is_left_out_PAC_args(data: bytes) -> bool:
    if len(data) % 8 != 0:
        return False

    # NB! So far this function returns false negative for args that only take up 4 bytes
    potential_args = [data[4 * i: 4 * i + 4] for i in range(0, len(data) // 4, 2)]
    for arg in potential_args:
        val = int.from_bytes(arg, "little")
        if val > 64 or val & (val - 1) != 0:  # val is not a power of 2
            return False
    return True

