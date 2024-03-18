
from typing import NamedTuple, List, Optional, Dict, Set
from Core.PAC.pac_file import (
    PAC_instruction, PAC_file
)
from Utils.utils import (
    in_between_bsearch, binary_search
)


# Maybe use dataclasses here?
class PAC_transition(NamedTuple):
    save_address: bool
    fallthrough: bool
    potential: bool
    special: bool
    callback: bool


class PAC_Edge:
    """
    The control-flow graph edge that goes from some block's exitpoint to some block's entrypoint
    """
    __slots__ = ("entry", "exit", "properties")

    def __init__(self):
        self.entry = EntryPoint()
        """
        The end of the edge
        """
        self.exit = ExitPoint()
        """
        The start of the edge
        """
        self.properties = PAC_transition(
            save_address=False,
            fallthrough=True,
            potential=False,
            special=False,
            callback=False
        )

    def __repr__(self):
        return f"Edge from 0x{self.exit.position:X} to 0x{self.entry.position:X}"

    def __str__(self):
        return f"Edge from 0x{self.exit.position:X} to 0x{self.entry.position:X}"


class EntryPoint:
    def __init__(self):
        self.where_from: List[PAC_Edge] = []
        self.position: int = 0
        self.instruction: Optional[PAC_instruction] = None
        self.code_block: Optional[ContiguousCodeBlock] = None

    def __repr__(self):
        ans = f"Entry point: file offset = 0x{self.position:X}"
        if self.instruction is not None:
            ans += f"; 0x{self.instruction.signature:X} ({self.instruction.name})"
        return ans

    def __str__(self):
        ans = f"Entry point: file offset = 0x{self.position:X}"
        if self.instruction is not None:
            ans += f"; 0x{self.instruction.signature:X} ({self.instruction.name})"
        return ans


class ExitPoint:
    def __init__(self):
        self.where_to: List[PAC_Edge] = []
        self.position: int = 0
        self.instruction: Optional[PAC_instruction] = None
        self.code_block: Optional[ContiguousCodeBlock] = None

    def __repr__(self):
        ans = f"Exit point: file offset = 0x{self.position:X}"
        if self.instruction is not None:
            ans += f"; 0x{self.instruction.signature:X} ({self.instruction.name})"
        return ans

    def __str__(self):
        ans = f"Exit point: file offset = 0x{self.position:X}"
        if self.instruction is not None:
            ans += f"; 0x{self.instruction.signature:X} ({self.instruction.name})"
        return ans


class RawDataBlock:
    def __init__(self):
        self.size: int = 0
        self.start: int = 0
        self.references_from: Dict[int] = {}
        self.data: bytes = b""
        self.shift_jis: Optional[str] = None

    def __repr__(self):
        return f"Raw data block (size = {self.size} bytes)"

    def __str__(self):
        return f"Raw data block (size = {self.size} bytes)"


class ContiguousCodeBlock:
    def __init__(self):
        self.size: int = 0
        self.start: int = 0
        self.instructions: Dict[int, PAC_instruction] = {}  # int is absolute file offset
        self.instructions_offsets: List[int] = []
        self.ordered_instructions: List[PAC_instruction] = []
        self.entry_points: Dict[int, EntryPoint] = {}
        self.exit_point: ExitPoint = ExitPoint()

        self.is_dummy: bool = False
        self.is_split: bool = False
        self.is_source: bool = True

    def __repr__(self):
        if self.is_dummy:
            return "Dummy code block"
        return f"Code block (number of instructions = {len(self.instructions)}, size = {self.size} bytes)"

    def __str__(self):
        if self.is_dummy:
            return "Dummy code block"
        return f"Code block (number of instructions = {len(self.instructions)}, size = {self.size} bytes)"

    def add_entrypoint_at(self, offset: int):
        """
        Creates a new entrypoint at the given offset\n
        :param offset: a PAC file offset
        :return: None
        """
        # Make the entry point
        entry_point = EntryPoint()
        entry_point.code_block = self
        entry_point.instruction = self.instructions[offset]
        entry_point.position = offset

        # Save the entry point
        self.entry_points[offset] = entry_point

    def accept_edge_to_entrypoint(self, entry: EntryPoint, exit_point: ExitPoint, transition: PAC_transition):
        """
        Creates and configures a PAC_edge, also marks the block as "not a source"\n
        :param entry: a valid entry point belonging to this block
        :param exit_point: some block's exitpoint
        :param transition: properties of this transition
        :return:
        """
        edge = PAC_Edge()
        edge.entry = entry
        edge.exit = exit_point
        edge.properties = transition

        edge.entry.where_from.append(edge)
        edge.exit.where_to.append(edge)

        self.is_source = False

    def accept_jump_to(self, to: int, exit_point: ExitPoint, transition: PAC_transition) -> bool:
        """
        Makes the block create a connection going from the exitpoint to the offset 'to'\n
        :param to: PAC offset which belongs to this block or precedes it
        :param exit_point: some block's exitpoint
        :param transition: properties of this transition
        :return: True on success
        """

        if self.instructions_offsets[-1] < to:
            # It's pointing past the block => report the issue
            return False

        if to < self.instructions_offsets[0]:
            # It's pointing before the block's start, but it's fine
            self.accept_edge_to_entrypoint(
                self.entry_points[self.start],
                exit_point,
                transition
            )
            return True

        # The offset is within the block now
        found, index = in_between_bsearch(self.instructions_offsets, to)

        if not found:
            # [instr_1] ... [instr_{index}] something [instr_{index+1}] ... [instr_{-1}]
            #                ^^^^^^^^^^^^^^ ^^^^^^^^^
            # It's either pointing within the instruction (but not at the start) or at "something"
            offset = self.instructions_offsets[index]
            instruction = self.ordered_instructions[index]
            if to < offset + instruction.size:
                return False

            # If we didn't return, 'to' is pointing at (or within) "something"
            # Ideally we gotta analyze this "something", but so far the blocks can't do that
            # TODO: make the blocks store the refs to the data within them and add some checks here

            # Propel 'to' forward
            to = self.instructions_offsets[index + 1]

        if to not in self.entry_points:
            self.add_entrypoint_at(to)

        self.accept_edge_to_entrypoint(
            self.entry_points[to],
            exit_point,
            transition
        )
        return True

    def to_dot_str(self):
        return "\\n".join([instr.name + f" (0x{offset:X})" for offset, instr in self.instructions.items()])

    def text_content(self):
        return "\\n".join([instr.name for instr in self.instructions.values()])

    def get_entry_point(self) -> EntryPoint:
        return next(iter(self.entry_points.values()))

    def get_incoming(self) -> List[PAC_Edge]:
        return self.get_entry_point().where_from

    def get_outgoing(self) -> List[PAC_Edge]:
        return self.exit_point.where_to


class BasePacCodeBlocks:
    def __init__(self, file: Optional[PAC_file] = None):
        self.file: PAC_file = file if file is not None else PAC_file()
        self.code_blocks: Dict[int, ContiguousCodeBlock] = {}
        self.block_start_offsets: List[int] = []

        self.cmd_end: int = 0
        self.cmd_call: int = 0
        self.cmd_jmp: int = 0
        self.cmd_inxJmp: int = 0
        self.cmd_stkDec: int = 0
        self.cmd_stkClr: int = 0
        self.cmd_setLabelId: int = 0
        self.cmd_callLabelId: int = 0
        self.cmd_jmpLabelId: int = 0
        self.cmd_callLabel: int = 0
        self.cmd_jmpLabel: int = 0
        self.doSelect: int = 0
        self.doSelectCursor: int = 0

        self.cond_jump_instructions: Dict[int, int] = {}
        self.uncond_jump_instructions: Dict[int, int] = {}
        self.jumping_instructions: Dict[int, int] = {}
        self.returning_instructions: List[int] = []
        self.saving_RA_instructions: Set[int] = set()
        self.callback_instructions: Dict[int, int] = {}

        self.verbose_level: int = 0
        self.signature_to_name: Dict[int, str] = {}

    def reset(self, file: PAC_file):
        raise NotImplementedError

    def get_block_by_offset(self, offset: int):
        """
            This function returns the block which contains the offset\n
            If there is none, it returns the block that goes right after the offset (if it is available)\n
            Else it returns None\n
            :param offset: the offset to look for
            :return: either None or a tuple of the real start offset and the block
        """

        if offset < 0:
            raise ValueError("Offset must be non-negative")

        first_offset = self.block_start_offsets[0]
        if offset < first_offset:
            # Can only happen if the file starts with some raw data
            return first_offset, self.code_blocks[first_offset]

        index = binary_search(self.block_start_offsets, offset)
        # Can't be -1 now

        block_start = self.block_start_offsets[index]
        block = self.code_blocks[block_start]
        if offset < block_start + block.size:
            # Offset belongs to this block
            return block_start, block

        # Now offset >= block_start + block.size

        # If it's not the last block, we return the next one
        if index != len(self.block_start_offsets) - 1:
            block_start = self.block_start_offsets[index + 1]
            return block_start, self.code_blocks[block_start]

        # Well, we tried
        return None

    def connect_location_to_offset(self, location: int, offset: int, transition: PAC_transition):
        """
        Creates an "exit point -> entry point" connection between two blocks\n
        :param location: a valid instruction offset
        :param offset: the destination offset (it can point to the padding before the actual instruction)
        :param transition: properties of this transition
        :return: -1 if it failed to get the block at offset, 0 if offset is not a valid instruction start, otherwise 1
        """

        # Let's see where this offset leads to
        res = self.get_block_by_offset(offset)
        if res is None:
            # Uncool, let's notify the user and continue
            return -1

        block_start, block = res
        if block_start > offset:
            # We decided to go with the next block
            if self.verbose_level <= 1:
                print("Using the next block.")

        # Let's make the block at offset do the job

        # Get the block at location
        our_block = self.get_block_by_offset(location)[1]
        # If the input is correct, this can't return None

        if not block.accept_jump_to(offset, our_block.exit_point, transition):
            return 0
        return 1

    def apply_conditional_jumps(self):
        """
        Creates the edges that come from the "if" instructions (2 branches for each)\n
        :return: None
        """
        for signature, index in self.cond_jump_instructions.items():
            if self.verbose_level <= 2:
                print(f"Processing {self.signature_to_name[signature]} ({signature:X})...")

            instructions = self.file.getInstructions(signature)
            for location, instruction in instructions.items():
                # Connect the block to the destination
                jumping_arg = instruction.ordered_PAC_params[index]
                offset = jumping_arg[1]
                save_address = signature in self.saving_RA_instructions
                transition = PAC_transition(
                    save_address=save_address, fallthrough=False, potential=False, special=False, callback=False
                )
                res = self.connect_location_to_offset(location, offset, transition)
                if self.verbose_level <= 3:
                    if res == -1:
                        print(f"Failed to get a block at offset 0x{offset:X}")
                    elif res == 0:
                        print(f"0x{offset:X} is not a valid instruction start!")

                # And now let's connect the consecutive blocks!
                transition = PAC_transition(
                    save_address=False, fallthrough=True, potential=False, special=False, callback=False
                )
                res = self.connect_location_to_offset(location, location + instruction.size, transition)
                if self.verbose_level <= 3:
                    if res != 1:
                        print(f"Attempt to connect {instruction.name} to the next instruction failed")

    def apply_cmd_inxJmp(self):
        """
        Creates the edges that come from the cmd_inxJmp instructions\n
        :return: None
        """
        for location, table in self.file.switch_case_tables.items():
            # We assume that switch-case tables are preceded by cmd_inxJmp instruction

            instr_offset, _ = self.file.get_entity_by_offset(location - 1)
            # Note: the following code repeatedly grabs the block where cmd_inxJmp is
            for offset in table.branches:
                transition = PAC_transition(
                    save_address=False, fallthrough=False, potential=False, special=False, callback=False
                )
                res = self.connect_location_to_offset(instr_offset, offset, transition)
                if self.verbose_level <= 3:
                    if res == -1:
                        print(f"Failed to get a block at offset 0x{offset:X}")
                    elif res == 0:
                        print(f"0x{offset:X} is not a valid instruction start!")

    def sort_jumps_from(self):
        """
        Makes sure that the lists of incoming edges for all entrypoints are sorted based on where they come from\n
        :return: None
        """
        for code_block in self.code_blocks.values():
            for entry_point in code_block.entry_points.values():
                entry_point.where_from.sort(key=lambda edge: edge.exit.position)

    def get_edges(self):
        """
        Get an iterable over all the edges in the code\n
        :return: the generator function
        """
        for block in self.code_blocks.values():
            yield from block.get_outgoing()

    def get_callback_edges(self):
        """
        Get an iterable over the edges that represent callbacks in the code\n
        :return: the generator function
        """
        for edge in self.get_edges():
            if edge.properties.callback:
                yield edge

    def get_unconditional_jumps(self):
        """
        Get an iterable over the edges that represent unconditional jumps in the code\n
        :return: the generator function
        """
        for edge in self.get_edges():
            if edge.exit.instruction.signature not in self.uncond_jump_instructions:
                continue
            if not edge.properties.save_address and not edge.properties.potential:
                yield edge

    def get_conditional_jumps(self):
        """
        Get an iterable over the edges that represent conditional jumps in the code\n
        (When the branch is taken)\n
        :return: the generator function
        """
        for edge in self.get_edges():
            if edge.exit.instruction.signature not in self.cond_jump_instructions:
                continue
            if not edge.properties.save_address:
                yield edge

    def get_switch_case_edges(self):
        """
        Get an iterable over the edges that represent possible switch-case jumps in the code\n
        :return: the generator function
        """
        for location, table in self.file.switch_case_tables.items():
            # 'location - sizeof(cmd_inxJmp)' is the start of cmd_inxJmp that lies in some block
            res = self.get_block_by_offset(location - 12)
            if not res:
                raise RuntimeError("Found switch-case table without the preceding cmd_inxJmp")
            _, block = res
            yield from block.get_outgoing()

    def get_unconditional_calls(self):
        """
        Get an iterable over the edges that represent unconditional calls in the code\n
        :return: the generator function
        """
        for edge in self.get_edges():
            if edge.exit.instruction.signature not in self.uncond_jump_instructions:
                continue
            if edge.properties.save_address:
                yield edge

    def get_conditional_calls(self):
        """
        Get an iterable over the edges that represent conditional calls in the code\n
        (When the branch is taken)\n
        :return: the generator function
        """
        for edge in self.get_edges():
            if edge.exit.instruction.signature not in self.cond_jump_instructions:
                continue
            if edge.properties.save_address:
                yield edge

    def get_unconditional_fallthrough_edges(self):
        """
        Get an iterable over the edges that represent the code flow between the split blocks\n
        :return: the generator function
        """
        for edge in self.get_edges():
            if not edge.properties.fallthrough:
                continue
            if edge.exit.code_block.is_split:
                yield edge

    def get_conditional_fallthrough_edges(self):
        """
        Get an iterable over the edges that represent the code flow when the branch is not taken\n
        :return: the generator function
        """
        for edge in self.get_edges():
            if not edge.properties.fallthrough:
                continue
            if not edge.exit.code_block.is_split:
                yield edge

    def get_special_edges(self):
        """
        Get an iterable over the special code references\n
        :return: the generator function
        """
        for edge in self.get_edges():
            if edge.properties.special:
                yield edge

    def get_potential_edges(self):
        """
        Get an iterable over the edges that represent potential code flow\n
        (after instructions that can force PAC_reader to return)\n
        :return: the generator function
        """
        for edge in self.get_edges():
            if not edge.properties.potential:
                continue
            if edge.exit.instruction.signature not in self.saving_RA_instructions:
                yield edge

    def get_step_over_edges(self):
        """
        Get an iterable over the edges that connect calling instructions to the next block\n
        (Hence the 'step over': it's when we'd go in the debugger after stepping over)\n
        :return: the generator function
        """
        for edge in self.get_edges():
            if not edge.properties.potential:
                continue
            if edge.exit.instruction.signature in self.saving_RA_instructions:
                yield edge

    def get_all_jumps(self):
        """
        Get an iterable over the edges that represent any jump in the code without saving the return address\n
        :return: the generator function
        """
        yield from self.get_unconditional_jumps()
        yield from self.get_conditional_jumps()
        yield from self.get_switch_case_edges()

    def get_all_calls(self):
        """
        Get an iterable over the edges that represent the jumps that save the return address\n
        :return: the generator function
        """
        for edge in self.get_edges():
            if edge.properties.save_address:
                yield edge

    def get_flow_truncators(self):
        """
        Get the offsets of cmd_end, cmd_stkDec and cmd_stkClr\n
        Note: their sizeof is 4\n
        :return: the generator function
        """
        yield from (offset for offset in self.file.getInstructions(self.cmd_end))
        yield from (offset for offset in self.file.getInstructions(self.cmd_stkDec))
        yield from (offset for offset in self.file.getInstructions(self.cmd_stkClr))

    def get_offsets_after_returning_instructions(self):
        """
        Get the offsets that go right after the returning instructions\n
        One of the values may be equal to the file size (=> be invalid)\n
        :return: the generator function
        """
        for signature in self.returning_instructions:
            yield from (
                location + instruction.size
                for location, instruction in self.file.getInstructions(signature).items()
            )
