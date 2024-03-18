
from Core.decompiler.pac_decompiler import (
    PAC_Decompiler
)
from Core.PAC.pac_file import (
    PAC_file
)
from Core.decompiler.code_blocs.base_pac_code_blocks import (
    ContiguousCodeBlock, RawDataBlock
)

from hashlib import md5
from typing import NamedTuple, Dict, List

from dataclasses import dataclass


class PAC_hasher:
    def hash(self, *args):
        raise NotImplementedError


class BytesHasher(PAC_hasher):
    def __init__(self):
        self.hasher = None

    def hash(self, file: PAC_file, code_block: ContiguousCodeBlock):
        raw = file.raw_data[code_block.start: code_block.start + code_block.size]
        self.hasher = md5()
        self.hasher.update(raw)
        return self.hasher.hexdigest()


class InstructionHasher(PAC_hasher):
    def __init__(self):
        self.hasher = None

    def hash(self, file: PAC_file, code_block: ContiguousCodeBlock):
        raw = bytearray()
        self.hasher = md5()
        for instr in code_block.ordered_instructions:
            signature = instr.raw_data[:4]
            raw.extend(signature)
        self.hasher.update(raw)
        return self.hasher.hexdigest()


class RawDataHasher(PAC_hasher):
    def __init__(self):
        self.hasher = None

    def hash(self, file: PAC_file, block: RawDataBlock):
        self.hasher = md5()
        self.hasher.update(block.data)
        return self.hasher.hexdigest()


@dataclass
class VTSettings:
    min_block_size: int = 0
    min_block_instr_count: int = 0
    unique_matches: bool = True
    non_unique_matches: bool = False


class PAC_Correlator:
    def __init__(self):
        self.first: PAC_Decompiler = PAC_Decompiler()
        self.second: PAC_Decompiler = PAC_Decompiler()
        self.settings = None

    def reset(self, first: PAC_Decompiler, second: PAC_Decompiler):
        self.first = first
        self.second = second

    def setSettings(self, settings: VTSettings):
        self.settings = settings

    def correlate(self):
        raise NotImplementedError


class PAC_match:
    def __init__(self):
        self.first_addresses: List[int] = []
        self.second_addresses: List[int] = []

    def add(self, address: int, is_first: bool):
        if is_first:
            self.first_addresses.append(address)
        else:
            self.second_addresses.append(address)


class MatchedCodeBlocks(NamedTuple):
    first: PAC_Decompiler
    second: PAC_Decompiler
    total_first: int
    total_second: int
    first_address: int
    second_address: int

    def __repr__(self):
        return f"Matched CodeBlocks: 0x{self.first_address:X} <-> 0x{self.second_address:X}"


class MatchedDataBlocks(NamedTuple):
    first: PAC_Decompiler
    second: PAC_Decompiler
    total_first: int
    total_second: int
    first_address: int
    second_address: int

    def __repr__(self):
        return f"Matched Data: 0x{self.first_address:X} <-> 0x{self.second_address:X}"


class CodeBlockMatcher:
    @staticmethod
    def hash_block(block_hashes: Dict[str, PAC_match], file: PAC_file, block: ContiguousCodeBlock, hasher: PAC_hasher,
                   is_first: bool):
        """
        Processes the code block and accumulates the hash info in block_hashes\n
        :param block_hashes: the mapping between the hashes and the matches
        :param file: the PAC file
        :param block: the code block
        :param hasher: the hasher object that will be used to process the block
        :param is_first: whether the file is the first one
        :return: None
        """
        block_hash = hasher.hash(file, block)
        submatch = block_hashes.get(block_hash, None)
        if submatch is None:
            submatch = PAC_match()
            block_hashes[block_hash] = submatch
        submatch.add(block.start, is_first)

    @staticmethod
    def match(first: PAC_Decompiler, second: PAC_Decompiler, hasher: PAC_hasher, settings: VTSettings):
        block_hashes: Dict[str, PAC_match] = {}
        matches: List[MatchedCodeBlocks] = []

        # Hash the first file's blocks
        for block in first.code.code_blocks.values():
            if block.size < settings.min_block_size:
                continue
            if len(block.instructions) < settings.min_block_instr_count:
                continue

            CodeBlockMatcher.hash_block(block_hashes, first.file, block, hasher, True)

        # Hash the second file's blocks
        for block in second.code.code_blocks.values():
            if block.size < settings.min_block_size:
                continue
            if len(block.instructions) < settings.min_block_instr_count:
                continue

            CodeBlockMatcher.hash_block(block_hashes, second.file, block, hasher, False)

        for match in block_hashes.values():
            first_addresses = match.first_addresses
            second_addresses = match.second_addresses
            first_count = len(first_addresses)
            second_count = len(second_addresses)

            if settings.unique_matches and first_count == 1 and second_count == 1:
                matches.append(
                    MatchedCodeBlocks(first, second, 1, 1, first_addresses[0], second_addresses[0])
                )
            if settings.non_unique_matches and not (first_count == 1 and second_count == 1):
                for first_address in first_addresses:
                    for second_address in second_addresses:
                        matches.append(
                            MatchedCodeBlocks(
                                first, second, first_count, second_count, first_address, second_address
                            )
                        )
        return matches


class DataBlockMatcher:
    @staticmethod
    def hash_data(data_hashes: Dict[str, PAC_match], file: PAC_file, block: RawDataBlock, hasher: PAC_hasher,
                  is_first: bool):
        """
        Processes the data block and accumulates the hash info in block_hashes\n
        :param data_hashes: the mapping between the hashes and the matches
        :param file: the PAC file
        :param block: the data block
        :param hasher: the hasher object that will be used to process the block
        :param is_first: whether the file is the first one
        :return:
        """
        data_hash = hasher.hash(file, block)
        submatch = data_hashes.get(data_hash, None)
        if submatch is None:
            submatch = PAC_match()
            data_hashes[data_hash] = submatch
        submatch.add(block.start, is_first)

    @staticmethod
    def match(first: PAC_Decompiler, second: PAC_Decompiler, hasher: PAC_hasher, settings: VTSettings):
        data_hashes: Dict[str, PAC_match] = {}
        matches: List[MatchedDataBlocks] = []

        # Hash the data in the first file
        for block in first.data.data_blocks.values():
            if block.size < settings.min_block_size:
                continue
            DataBlockMatcher.hash_data(data_hashes, first.file, block, hasher, True)

        # Hash the data in the second file
        for block in second.data.data_blocks.values():
            if block.size < settings.min_block_size:
                continue
            DataBlockMatcher.hash_data(data_hashes, second.file, block, hasher, False)

        for match in data_hashes.values():
            first_addresses = match.first_addresses
            second_addresses = match.second_addresses
            first_count = len(first_addresses)
            second_count = len(second_addresses)

            if settings.unique_matches and first_count == 1 and second_count == 1:
                matches.append(
                    MatchedDataBlocks(first, second, 1, 1, first_addresses[0], second_addresses[0])
                )
            if settings.non_unique_matches and not (first_count == 1 and second_count == 1):
                for first_address in first_addresses:
                    for second_address in second_addresses:
                        matches.append(
                            MatchedDataBlocks(
                                first, second, first_count, second_count, first_address, second_address
                            )
                        )
        return matches


class BytesCorrelator(PAC_Correlator):
    def __init__(self):
        super().__init__()

    def correlate(self):
        hasher = BytesHasher()
        res = CodeBlockMatcher.match(self.first, self.second, hasher, self.settings)
        return res


class InstructionsCorrelator(PAC_Correlator):
    def __init__(self):
        super().__init__()

    def correlate(self):
        hasher = InstructionHasher()
        res = CodeBlockMatcher.match(self.first, self.second, hasher, self.settings)
        return res


class DataCorrelator(PAC_Correlator):
    def __init__(self):
        super().__init__()

    def correlate(self):
        hasher = RawDataHasher()
        res = DataBlockMatcher.match(self.first, self.second, hasher, self.settings)
        return res


class PAC_VtSession:
    def __init__(self):
        self.first: PAC_Decompiler = PAC_Decompiler()
        self.second: PAC_Decompiler = PAC_Decompiler()

    def reset(self, first: PAC_Decompiler, second: PAC_Decompiler):
        self.first = first
        self.second = second

    def correlate(self, correlator: PAC_Correlator):
        correlator.reset(self.first, self.second)
        res = correlator.correlate()
        # For now...
        return res

    def postprocess_results(self, res: List[MatchedCodeBlocks]):
        res.sort(key=lambda m: self.first.code.code_blocks[m.first_address].size, reverse=True)
        print("Results sorted!")

    def make_dot_file_for_matches(self, matched: List[MatchedCodeBlocks], is_first: bool):
        if is_first:
            offsets = {m.first_address for m in matched}
            self.first.setMatchedOffsets(offsets)
            return self.first.make_dot_file()
        else:
            offsets = {m.second_address for m in matched}
            self.second.setMatchedOffsets(offsets)
            return self.second.make_dot_file()
