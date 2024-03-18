
from typing import Optional, Dict, Set

from Core.decompiler.code_blocs.base_pac_code_blocks import (
    BasePacCodeBlocks, ContiguousCodeBlock
)
from Core.decompiler.code_blocs.pac_code_blocks import (
    PAC_CodeBlocks
)
from Core.PAC.pac_file import (
    PAC_file
)
from Utils.utils import (
    binary_search
)


def get_subroutine_possible_starts(code_blocks: PAC_CodeBlocks):
    """
    Returns all possible start offsets for the PAC subroutines (they need to be filtered later)\n
    :param code_blocks: the initialized code blocks
    :return: the set of valid file offsets
    """
    ans: Set[int] = set()
    # 1) some destinations of the edges
    # We don't need the possible edges that come from cmd_call / cmd_callLabel / cmd_callLabelId:
    all_destinations: Set[int] = {i.entry.position for i in code_blocks.get_edges()}
    bad_destinations: Set[int] = {i.entry.position for i in code_blocks.get_step_over_edges()}
    destinations = all_destinations - bad_destinations
    ans.update(destinations)

    # 2) the offsets after of the instructions that jump without saving the RA
    all_jump_locations: Set[int] = {i.exit.position + i.exit.instruction.size for i in code_blocks.get_all_jumps()}
    ans.update(all_jump_locations)

    # 3) the offsets after the returning instructions (remove the invalid one, if it's there)
    returning = set(code_blocks.get_offsets_after_returning_instructions())
    returning.discard(code_blocks.file.size)
    ans.update(returning)

    # 4) the offsets after the flow-truncators cmd_end, cmd_stkDec and cmd_stkClr
    # (except for the possible invalid one)
    truncators: Set[int] = {offset + 4 for offset in code_blocks.get_flow_truncators()}
    truncators.discard(code_blocks.file.size)
    ans.update(truncators)

    return ans


class PAC_FunctionBlocks(BasePacCodeBlocks):
    def __init__(self, file: Optional[PAC_file] = None):
        super().__init__(file)

    def reset(self, file: PAC_file):
        self.file = file
        self.code_blocks: Dict[int, ContiguousCodeBlock] = {}
        self.block_start_offsets = []

    def construct_block(self, start: int, end: int):
        """
        Creates a basic block from all PAC instructions found in the specified range\n
        :param start: the start of the range, inclusive
        :param end: the end of the range, exclusive
        :return:
        """
        block = ContiguousCodeBlock()

        start_index = binary_search(self.file.instructions_offsets, start)
        end_index = binary_search(self.file.instructions_offsets, end)
        for i in range(start_index, end_index):
            offset = self.file.instructions_offsets[i]
            instruction = self.file.ordered_instructions[offset]

            block.instructions[offset] = instruction
            block.ordered_instructions.append(instruction)
            block.instructions_offsets.append(offset)
        block.start = self.file.instructions_offsets[start_index]
        # block.size =
        pass

    def break_into_blocks(self, code_blocks: PAC_CodeBlocks):
        # We run a similar algorithm to split the code into blocks, but this time we know where to split
        # => we have no need for normalizing entrypoints after that.
        possible_offsets = sorted(get_subroutine_possible_starts(code_blocks))
        # print("\n".join((f"0x{offset:X}" for offset in possible_offsets)))
        if len(possible_offsets) == 1:
            raise RuntimeError("Exactly one code block boundary!")
        last_offset = possible_offsets[0]
        for offset in possible_offsets[1:]:
            # [last_offset; offset)
            self.construct_block(last_offset, offset)

            # Update the last offset
            last_offset = offset


