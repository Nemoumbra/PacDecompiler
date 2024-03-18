
from typing import List, Tuple, Any, Callable

import struct
import sys
import os
from pathlib import Path


def resource_path(relative_path: str) -> Path:
    if hasattr(sys, "_MEIPASS"):
        current_path = Path(sys._MEIPASS)
    else:
        current_path = Path(os.path.dirname(__file__))
    return current_path.joinpath(relative_path)


def load_file_by_path(path: str) -> bytes:
    """
    Reads the file with given path in binary mode and returns the bytes object
    :param path: input path
    :return:
    """
    with open(path, "rb") as source:
        return source.read()


def read_string_from_bytes(data: bytes, offset: int, length: int = -1) -> str:
    """
    If length is -1, reads bytes one by one in utf-8 encoding until the zero byte is read
    (NOTE: the zero byte is not included in the resulting string!)
    If length is not -1, calls bytes.decode("utf-8")
    (NOTE: in this case the zero byte is not trimmed if it ends up in the range!)
    :param data: the raw data to read from
    :param offset: the offset to read from
    :param length: either -1 for unspecified length or the string length
    :return: the resulting string
    """
    res = ""
    if length == -1:
        address = offset
        one_byte = data[address:address + 1]
        val = int.from_bytes(one_byte, "big")
        char = one_byte.decode("utf-8")
        while val != 0:
            res += char
            address += 1
            one_byte = data[address:address + 1]
            val = int.from_bytes(one_byte, "big")
            char = one_byte.decode("utf-8")
    else:
        raw = data[offset:offset + length]
        res = raw.decode("utf-8")
    return res


def read_shift_jis_from_bytes(data: bytes, offset: int, length: int = -1) -> str:
    """
    If length is -1, reads groups of 2 bytes in shift-jis encoding until the zero byte is read
    (NOTE: the zero byte is not included in the resulting string!)
    If length is not -1, calls bytes.decode("shift-jis")
    (NOTE: in this case the zero byte is not trimmed if it ends up in the range!)
    :param data: the raw data to read from
    :param offset: the offset to read from
    :param length: either -1 for unspecified length or the string length
    :return: the resulting string
    """
    res = ""
    if length == -1:
        address = offset
        two_bytes = data[address:address + 2]
        val = int.from_bytes(two_bytes, "big")
        char = two_bytes.decode("shift-jis")
        while val != 0:
            res += char
            address += 2
            two_bytes = data[address:address + 2]
            val = int.from_bytes(two_bytes, "big")
            char = two_bytes.decode("shift-jis")
    else:
        raw = data[offset:offset + length]
        res = raw.decode("shift-jis")
    return res
    pass


def read_wstring_from_bytes(data: bytes, offset: int, length: int = -1) -> str:
    """
    :param data: bytes object
    :param offset: offset
    :param length: [optional] length of the range measured in characters
    :return: wide string in the utf-16 encoding
    """
    # If length is -1, reads groups of 2 bytes in utf - 16 encoding until the zero byte is read
    # (NOTE: the zero byte is not included in the resulting string!)
    # If length is not -1, calls bytes.decode("utf-16")
    # (NOTE: in this case the zero byte is not trimmed if it ends up in the range!)
    res = ""
    if length == -1:
        address = offset
        two_bytes = data[address:address + 2]
        val = int.from_bytes(two_bytes, "big")
        char = two_bytes.decode("utf-16")
        while val != 0:
            res += char
            address += 2
            two_bytes = data[address:address + 2]
            val = int.from_bytes(two_bytes, "big")
            char = two_bytes.decode("utf-16")
    else:
        raw = data[offset:offset + 2 * length]
        res = raw.decode("utf-16")
    return res
    pass


def read_int_from_bytes(data: bytes, offset: int, byteorder: str) -> int:
    """
    :param data: bytes object
    :param offset: offset
    :param byteorder: either "little" or "big"
    :return:
    """
    four_bytes = data[offset:offset + 4]
    val = int.from_bytes(four_bytes, byteorder)
    return val


def read_custom_int_from_bytes(data: bytes, offset: int, sizeof: int, byteorder: str) -> int:
    """
    :param data: bytes object
    :param offset: offset
    :param sizeof: the size of the integer in bytes
    :param byteorder: either "little" or "big"
    :return:
    """
    value_bytes = data[offset:offset + sizeof]
    val = int.from_bytes(value_bytes, byteorder)
    return val


def read_float_from_bytes(data: bytes, offset: int) -> float:
    """
    Reads the f32 float
    :param data: bytes object
    :param offset: offset
    :return:
    """
    four_bytes = data[offset:offset + 4]
    val = struct.unpack("f", four_bytes)[0]
    return val


def binary_search(array: List, val: int) -> int:
    """
    This is the lower bound binary search:
     - if array contains val, returns its index\n
     - if val is bigger than every array element, returns the last index\n
     - if array[i] < val < array[i+1], returns i\n
     - if val is less than every array element, returns -1
    :param array: a list to conduct the search in
    :param val: the value to search for
    """
    if not array:
        raise ValueError("List must not be empty!")
    lo = -1
    hi = len(array)
    while hi - lo > 1:
        mid = (hi + lo) // 2
        if array[mid] < val:
            lo = mid
        else:
            hi = mid

    # if hi == len(array) => hi was never assigned to =>
    # => for every array element x statement "val > x" holds =>
    # => val is bigger than any element in array =>
    # => we return the last index == lo
    if hi == len(array):
        return lo
    # else there has been at least one assignment to hi =>
    # there is at least one k such that val <= array[k] =>
    # in the end val <= array[hi]

    # it's useless to compare array[lo] and val as array[lo] is always less than val
    # if element is found, we just return the index
    if array[hi] == val:
        return hi
    # else either lo == -1 (val is less than every array element)
    # or array[lo] < val < array[hi] => we return lo
    return lo


def binary_search_lambda(array: List, val: int, key: Callable[[Any], int]) -> int:
    """
    This is the lower bound binary search:
     - if array contains val, returns its index
     - if val is bigger than every array element, returns the last index
     - if array[i] < val < array[i+1], returns i
     - if val is less than every array element, returns -1
    :param array: a list to conduct the search in
    :param val: the value to search for
    :param key: the lambda function used when comparing array[mid] and val
    """
    if not array:
        raise ValueError("List must not be empty!")
    lo = -1
    hi = len(array)
    while hi - lo > 1:
        mid = (hi + lo) // 2
        if key(array[mid]) < val:
            lo = mid
        else:
            hi = mid

    # if hi == len(array) => hi was never assigned to =>
    # => for every array element x statement "val > x" holds =>
    # => val is bigger than any element in array =>
    # => we return the last index == lo
    if hi == len(array):
        return lo
    # else there has been at least one assignment to hi =>
    # there is at least one k such that val <= array[k] =>
    # in the end val <= array[hi]

    # it's useless to compare array[lo] and val as array[lo] is always less than val
    # if element is found, we just return the index
    if key(array[hi]) == val:
        return hi
    # else either lo == -1 (val is less than every array element)
    # or array[lo] < val < array[hi] => we return lo
    return lo


def contains_bsearch(array: List, val: int) -> bool:
    """
    This binary search does the same thing as the operator "in", but faster - O(log(n))\n
    :param array: a sorted list to conduct the search in
    :param val: the value to search for
    :return: boolean value: does the array contain val?
    """
    if not array:
        raise ValueError("List must not be empty!")
    lo = -1
    hi = len(array)
    while hi - lo > 1:
        mid = (hi + lo) // 2
        if array[mid] < val:
            lo = mid
        else:
            hi = mid
    # if val in array, then its index is hi
    if hi == len(array):
        return False
    return array[hi] == val


def in_between_bsearch(array: List, val: int) -> Tuple[bool, int]:
    """
    This binary search is for finding the index i of val or squeezing val between the indexes i and i+1
    (array[i] < val < array[i+1])
    Note: if val is not within [array[0]; array[-1]], the behaviour is undefined!
    :param array: a sorted list to conduct the search in
    :param val: the value to search for
    :return: a tuple (found, i)
    """
    if not array:
        raise ValueError("List must not be empty!")
    lo = -1
    hi = len(array)
    while hi - lo > 1:
        mid = (hi + lo) // 2
        if array[mid] < val:
            lo = mid
        else:
            hi = mid
    # Here we assume that val is not bigger than all of the array elements =>
    # => hi was assigned at least once => it's a valid index
    # We also assume that val is not less than all of the array elements => lo > -1

    # Therefore, array[lo] < val <= array[hi]

    # if val in array, then its index is hi
    if array[hi] == val:
        return True, hi

    # Then array[lo] < val < array[hi] => we return lo
    return False, lo


def unpack_int_from_bytes(int_bytes: bytes) -> int:
    """
    Use this as a 'map' argument if you ever need to turn bytes into ints
    :param int_bytes: bytes
    :return: the converted integer
    """
    return int.from_bytes(int_bytes, "little")


def print_hex(L: List[int]):
    """
    Prints the comma-separated list of values from the specified list inside the square brackets
    :param L: the list
    :return: None
    """
    print("[" + ", ".join(f"0x{elem:X}" for elem in L) + "]")
