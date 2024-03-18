
from typing import List, Optional, Dict, Set
from Core.PAC.pac_file import (
    PAC_instruction, PAC_file, PAC_variable, associate_pac_vars_and_instr
)
from Utils.utils import (
    binary_search, print_hex
)
from Core.decompiler.code_blocs.base_pac_code_blocks import (
    BasePacCodeBlocks, ContiguousCodeBlock, EntryPoint, PAC_transition, PAC_Edge
)

from pathlib import Path


class PAC_CodeBlocks(BasePacCodeBlocks):
    def __init__(self, file: Optional[PAC_file] = None):
        super().__init__(file)

        self.label_to_offset: Dict[int, Set[int]] = {}
        self.unrecovered_jumps: Dict[int, PAC_variable] = {}  # offset -> variable
        self.getGateInfo_block_offsets: Set[int] = set()
        self.split_blocks: Dict[int, List[int]] = {}
        self.callback_destinations: Dict[int, int] = {}

    def reset(self, file: PAC_file):
        self.file = file
        self.code_blocks: Dict[int, ContiguousCodeBlock] = {}
        self.block_start_offsets = []
        self.label_to_offset = {}
        self.unrecovered_jumps = {}
        self.getGateInfo_block_offsets = set()
        self.split_blocks = {}
        self.callback_destinations = {}

    def read_instructions_info(self, cond_path, uncond_path, jump_path, returning_path, saving_path, callback_path):
        def read_dict(path):
            info: Dict[int, int] = {}
            with open(path, encoding="utf-8") as file:
                for line in file:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    if stripped[0] == "#":
                        continue
                    signature, arg_index = stripped.split(" ")
                    info[int(signature, 16)] = int(arg_index)
            return info

        def read_list(path):
            info: List[int] = []
            with open(path, encoding="utf-8") as file:
                for line in file:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    if stripped[0] == "#":
                        continue
                    info.append(int(stripped, 16))
            return info

        self.cond_jump_instructions = read_dict(cond_path)
        self.uncond_jump_instructions = read_dict(uncond_path)
        self.jumping_instructions = read_dict(jump_path)
        self.returning_instructions = read_list(returning_path)
        self.saving_RA_instructions = set(read_list(saving_path))
        self.callback_instructions = read_dict(callback_path)

    def read_important_signatures(self, signatures_path):
        def read_important(ins_list: List[int]):
            yield from ins_list

        with open(signatures_path) as file:
            signatures = list(map(lambda x: int(x, 16), [line.strip() for line in file]))
            signatures = read_important(signatures)

            self.cmd_end = next(signatures)
            self.cmd_jmp = next(signatures)
            self.cmd_call = next(signatures)
            self.cmd_inxJmp = next(signatures)
            self.cmd_stkDec = next(signatures)
            self.cmd_stkClr = next(signatures)
            self.cmd_setLabelId = next(signatures)
            self.cmd_callLabelId = next(signatures)
            self.cmd_jmpLabelId = next(signatures)
            self.cmd_callLabel = next(signatures)
            self.cmd_jmpLabel = next(signatures)
            self.doSelect = next(signatures)
            self.doSelectCursor = next(signatures)

    def set_signature_to_name(self, matching: Dict[int, str]):
        self.signature_to_name = matching

    def break_into_blocks(self, include_callbacks: bool):
        special_signatures = set(self.returning_instructions).union(self.jumping_instructions.keys())

        # Flow truncators
        special_signatures.update({self.cmd_end, self.cmd_stkDec, self.cmd_stkClr})

        if include_callbacks:
            special_signatures = special_signatures.union(self.callback_instructions.keys())

        current_block = ContiguousCodeBlock()
        # Damn this is ugly...
        current_location: int = 0
        current_instr_size: int = 0
        start: int = -1

        for location, instruction in self.file.ordered_instructions.items():
            # This is saved so that it could be accessed after the loop is over
            current_location, current_instr_size = location, instruction.size
            # This is a weird signal that we need to reset start
            if start < 0:
                start = location

            current_block.instructions[location] = instruction
            current_block.ordered_instructions.append(instruction)
            current_block.instructions_offsets.append(location)
            if instruction.signature in special_signatures:
                # End current block with this instruction and start a new one
                current_block.start = start
                current_block.size = location + instruction.size - start

                current_block.exit_point.position = location
                current_block.exit_point.instruction = instruction
                current_block.exit_point.code_block = current_block

                self.code_blocks[current_block.start] = current_block
                # start += current_block.size  # This is erroneous...
                start = -1

                current_block = ContiguousCodeBlock()

        if current_block.instructions:
            current_block.start = list(current_block.instructions.keys())[0]  # I guess that's not too efficient...
            current_block.size = current_location + current_instr_size - start

            current_block.exit_point.position = current_location
            current_block.exit_point.instruction = self.file.ordered_instructions[-1]

            self.code_blocks[current_block.start] = current_block

        # Now let's initialize entry points and exit points
        for start, block in self.code_blocks.items():
            entry_point = EntryPoint()
            entry_point.position = start
            entry_point.instruction = block.instructions[start]
            entry_point.code_block = block
            # Here we don't assign entry_point.where_from
            block.entry_points[start] = entry_point

        # Finally, let's compute this
        self.block_start_offsets = list(self.code_blocks.keys())

    def apply_unconditional_jumps(self):
        for signature, index in self.uncond_jump_instructions.items():
            if self.verbose_level <= 2:
                print(f"Processing {self.signature_to_name[signature]} ({signature:X})...")
            instructions = self.file.getInstructions(signature)
            for location, instruction in instructions.items():
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

                # The general code would've been 'if signature in save_address'
                if signature == self.cmd_call:
                    transition = PAC_transition(
                        save_address=False, fallthrough=False, potential=True, special=False, callback=False
                    )
                    res = self.connect_location_to_offset(location, location + instruction.size, transition)
                    if self.verbose_level <= 3:
                        if res != 1:
                            print(f"Attempt to connect {instruction.name} to the next instruction failed")

    def elementary_label_study(self):
        cmd_setLabelId_instructions = self.file.getInstructions(self.cmd_setLabelId)
        if not cmd_setLabelId_instructions:
            if self.verbose_level <= 2:
                print("Thankfully, no cmd_setLabelId instructions found.")
        else:
            for _, instruction in cmd_setLabelId_instructions.items():
                index_arg = instruction.ordered_PAC_params[0]
                offset_arg = instruction.ordered_PAC_params[1]
                if index_arg[0].type != "uint32_t":
                    if self.verbose_level <= 3:
                        print(f"Label index is passed through {index_arg[0].type}!")
                    continue
                if index_arg[1] not in self.label_to_offset:
                    self.label_to_offset[index_arg[1]] = set()
                self.label_to_offset[index_arg[1]].add(offset_arg[1])
            if self.verbose_level <= 2:
                print("Label table done...")

        # Now we assume that any cmd_CallLabelId and cmd_jmpLabelId might jump there
        for signature in (self.cmd_jmpLabelId, self.cmd_callLabelId):
            if self.verbose_level <= 2:
                print(f"Processing {self.signature_to_name[signature]} ({signature:X})...")
            instructions = self.file.getInstructions(signature)

            for location, instruction in instructions.items():
                index_arg = instruction.ordered_PAC_params[0]
                if index_arg[0].type != "uint32_t":
                    print(f"Label index is passed through {index_arg[0].type}!")
                    continue
                if index_arg[1] not in self.label_to_offset:
                    print(f"Unknown label {index_arg[1]} accessed at 0x{location:X}!")
                    continue

                # Else we can do our job
                offsets = self.label_to_offset[index_arg[1]]
                save_address = instruction.signature in self.saving_RA_instructions
                for offset in offsets:
                    transition = PAC_transition(
                        save_address=save_address, fallthrough=False, potential=False, special=False, callback=False
                    )
                    res = self.connect_location_to_offset(location, offset, transition)
                    if self.verbose_level <= 3:
                        if res == -1:
                            print(f"Failed to get a block at offset 0x{offset:X}")
                        elif res == 0:
                            print(f"0x{offset:X} is not a valid instruction start!")

    def elementary_runtime_jump_study(self):
        # This function just connects cmd_CallLabel instructions to the following blocks

        signatures = (self.cmd_jmpLabel, self.cmd_callLabel)
        for signature in signatures:
            if self.verbose_level <= 2:
                print(f"Processing {self.signature_to_name[signature]} ({signature:X})...")
            instructions = self.file.getInstructions(signature)

            for location, instruction in instructions.items():
                if signature in self.saving_RA_instructions:
                    # Let's connect it to the next block
                    transition = PAC_transition(
                        save_address=False, fallthrough=False, potential=True, special=False, callback=False
                    )
                    res = self.connect_location_to_offset(location, location + instruction.size, transition)
                    if self.verbose_level <= 3:
                        if res != 1:
                            print(f"Attempt to connect {instruction.name} to the next instruction failed")

    def attempt_variable_recovery(self, references: Dict[int, Dict[int, PAC_instruction]],
                                  variable_to_offset: Dict[PAC_variable, List[int]]):
        # Reminder: 'references[variable_index]' is a dict of (location -> instruction)
        # It stores all instructions which use IntLocal[variable_index]

        # Note: this function was made with the runtime jumps in mind
        # It won't attempt to recover other variables

        signatures = (self.cmd_jmpLabel, self.cmd_callLabel)

        recovered_variables: Dict[PAC_variable, int] = {}
        # Now let's iterate over the variables and examine them
        for variable, instructions_offsets in variable_to_offset.items():
            var_type = variable.type

            # Sanity checks
            if "variable" not in var_type:
                if self.verbose_level <= 3:
                    print(f"Following instructions received their jumping arg as {var_type}")
                    print_hex(instructions_offsets)
                # Maybe do something else here
                continue

            if var_type.startswith("0x40") or var_type.startswith("0x20"):
                if self.verbose_level <= 3:
                    print(f"Following instructions received their jumping arg as a floating {var_type}")
                    print_hex(instructions_offsets)
                # Maybe do something else here
                continue

            if var_type.startswith("0x8"):
                if self.verbose_level <= 3:
                    print(f"Following instructions received their jumping arg as IntGlobal")
                    print_hex(instructions_offsets)
                # Maybe still examine them?
                continue

            # Now then... Only IntLocals
            who_uses_this = references[variable.value]

            # Let's filter out the actual cmd_callLabel and cmd_jmpLabel instructions
            who_uses_this = {
                offset: instr
                for offset, instr in who_uses_this.items() if instr.signature not in signatures
            }

            # Questionable, but let's go with this for now
            # Let's keep the instructions which receive exactly one 0x1 argument
            who_uses_this = {
                offset: instr
                for offset, instr in who_uses_this.items() if len(instr.get_used_0x1_values()) == 1
            }

            if self.verbose_level <= 2:
                print(f"IntLocal {variable.value:X}:", end=" ")

            # Now there are a few cases. The best one is the following:
            if len(who_uses_this) == 1:
                offset: int = next(iter(who_uses_this))
                instr: PAC_instruction = who_uses_this[offset]

                if self.verbose_level <= 2:
                    print(f"only one instruction refers to it: {instr} at 0x{offset:X}")

                # Great, now let's have a look at the argument to get our value
                # Actually, we don't know which argument stores it, so let's just take all of them
                _0x1_args = instr.get_used_0x1_values()

                if len(_0x1_args) != 1:
                    # That's very unlikely, but let's just keep it here as a safety measure
                    if self.verbose_level <= 2:
                        print("But it doesn't use exactly one 0x1 value... :(")
                else:
                    _0x1_value = _0x1_args[0]  # <----- finally, our value
                    if self.verbose_level <= 2:
                        print(f"0x1 value = 0x{_0x1_value:X}")
                    # Now let's save this info
                    recovered_variables[variable] = _0x1_value

            elif len(who_uses_this) < 15:
                if self.verbose_level <= 2:
                    print(f"it's used {len(who_uses_this)} times")
                    print(who_uses_this)
                    print("Just the locations:", end=" ")
                    print_hex(list(who_uses_this.keys()))
            else:
                if self.verbose_level <= 2:
                    print("too many references to list :(")
        return recovered_variables

    def intermediate_runtime_jump_study(self):
        signatures = (self.cmd_jmpLabel, self.cmd_callLabel)

        # We build the mapping between the runtime-jumping instructions' positions
        # and the variables which act as a storage for the destinations
        offset_to_jumping_variable: Dict[int, PAC_variable] = {}
        for signature in signatures:
            if self.verbose_level <= 2:
                print(f"Processing {self.signature_to_name[signature]} ({signature:X})...")
            instructions = self.file.getInstructions(signature)
            for location, instruction in instructions.items():
                # It's the only hardcoded part: the destination is contained in the first argument
                jumping_arg = instruction.ordered_PAC_params[0]
                offset_to_jumping_variable[location] = PAC_variable(jumping_arg[0].type, jumping_arg[1])

        # Now let's reverse the dictionary: PAC_variable -> List[instruction location]
        variable_to_offset: Dict[PAC_variable, List[int]] = {}
        for location, variable in offset_to_jumping_variable.items():
            if variable not in variable_to_offset:
                variable_to_offset[variable] = []
            variable_to_offset[variable].append(location)

        # We're gonna assume that only IntLocals can be used for the destination
        references, _, _, _ = associate_pac_vars_and_instr(self.file)
        # 'references[variable_index]' is a dict of (location -> instruction)
        # It stores all instructions which use IntLocal[variable_index]

        # If we're lucky, we'll be able to uniquely identify the values that are stored in these variables
        recovered_variables = self.attempt_variable_recovery(references, variable_to_offset)

        # We could have recovered some branches
        recovered_jumps_count = 0
        for variable, offsets in variable_to_offset.items():
            # Time to see if we were lucky with this variable
            if variable not in recovered_variables:
                for offset in offsets:
                    self.unrecovered_jumps[offset] = variable
                # Let's try another variable
                continue

            # We're here => we've recovered this jump
            # That means we can now update all the places where this variable is used
            for offset in offsets:
                save_ra = self.file.ordered_instructions[offset].signature in self.saving_RA_instructions
                transition = PAC_transition(
                    save_address=save_ra, fallthrough=False, potential=False, special=False, callback=False
                )
                res = self.connect_location_to_offset(offset, recovered_variables[variable], transition)
                if res == -1:
                    if self.verbose_level <= 3:
                        print(f"Failed to get a block at offset 0x{offset:X}")
                elif res == 0:
                    if self.verbose_level <= 3:
                        print(f"0x{offset:X} is not a valid instruction start!")
                else:
                    recovered_jumps_count += 1
        if self.verbose_level <= 2:
            print(f"Recovered jumps count = {recovered_jumps_count}")
            print("Unrecovered jumps:", self.unrecovered_jumps)
            print("Hex instruction offsets: ", end="")
            print_hex(list(self.unrecovered_jumps.keys()))

        # Let's see how many jumps follow the rule "getGateInfo -> cmd_jumpLabel/cmd_callLabel" ...
        for offset in self.unrecovered_jumps:
            index = binary_search(self.file.entities_offsets, offset)
            if index == 0:
                if self.verbose_level <= 3:
                    print(f"The first file entity is {self.file.entities[index].name}")
                continue
            previous = self.file.entities[self.file.entities_offsets[index - 1]]
            if type(previous) is not PAC_instruction or previous.signature != 0x2516BE00:
                # not getGateInfo
                if self.verbose_level <= 3:
                    print(f"Unrecognized runtime jump practice: getGateInfo does not precede 0x{offset:X}")
                continue
            # Recognized pattern...!
            self.getGateInfo_block_offsets.add(self.get_block_by_offset(offset)[0])

    def apply_returning_instructions(self):
        if self.verbose_level <= 2:
            print("Step 6: apply returning instructions...")
        for signature in self.returning_instructions:

            # doSelect and doSelectCursor get special treatment
            if signature == self.doSelect or signature == self.doSelectCursor:
                instruction_name = self.signature_to_name[signature]
                if self.verbose_level <= 2:
                    print(f"Processing {instruction_name}...")
                instructions = self.file.getInstructions(signature)
                for location, instruction in instructions.items():
                    jumping_offset = instruction.ordered_PAC_params[0][1]
                    res = self.get_block_by_offset(jumping_offset)
                    if res is None or res[0] != jumping_offset:
                        if self.verbose_level <= 2:
                            print(f"Unrecognized {instruction_name} usage practice at 0x{location:X}!")
                    else:
                        _, block = res
                        transition = PAC_transition(
                            save_address=False, fallthrough=False, potential=False, special=True, callback=False
                        )
                        res = self.connect_location_to_offset(location, jumping_offset, transition)
                        if self.verbose_level <= 2:
                            if res != 1:
                                print(f"For some reason {instruction_name} connection failed at 0x{location:X}")
                continue

            # Ordinary instructions
            if self.verbose_level <= 2:
                print(f"Processing {self.signature_to_name[signature]}...")
            instructions = self.file.getInstructions(signature)
            for location, instruction in instructions.items():
                transition = PAC_transition(
                    save_address=False, fallthrough=False, potential=True, special=False, callback=False
                )
                res = self.connect_location_to_offset(location, location + instruction.size, transition)
                if self.verbose_level <= 2:
                    if res != 1:
                        print(f"Attempt to connect {instruction.name} to the next instruction failed")

    def apply_callbacks(self):
        if self.verbose_level <= 2:
            print("Step 7: apply callback instructions...")
        for signature, index in self.callback_instructions.items():
            if self.verbose_level <= 2:
                print(f"Processing {self.signature_to_name[signature]}...")

            instructions = self.file.getInstructions(signature)
            for location, instruction in instructions.items():
                transition = PAC_transition(
                    save_address=False, fallthrough=False, potential=False, special=False, callback=False
                )
                res = self.connect_location_to_offset(location, location + instruction.size, transition)
                if res != 1:
                    if self.verbose_level <= 3:
                        print(f"Attempt to connect {instruction.name} to the next instruction failed")
                else:
                    block: ContiguousCodeBlock
                    _, block = self.get_block_by_offset(location)
                    block.is_split = True  # for the SVG graph

                # Now then... Let's see if the last instruction actually makes a callback
                callback_param, offset = instruction.ordered_PAC_params[index]
                arg_type = callback_param.type
                if arg_type.startswith("0x1") or arg_type.startswith("uint32_t_P") or arg_type.startswith("uintX_t"):
                    # It is a callback
                    transition = PAC_transition(
                        save_address=False, fallthrough=False, potential=False, special=False, callback=True
                    )
                    res = self.connect_location_to_offset(location, offset, transition)
                    if res == -1:
                        if self.verbose_level <= 2:
                            print(f"Failed to get a block at offset 0x{offset:X}")
                    elif res == 0:
                        if self.verbose_level <= 2:
                            print(f"0x{offset:X} is not a valid instruction start!")
                    else:
                        self.callback_destinations[location] = offset
                else:
                    # Do nothing
                    pass
        if self.verbose_level <= 2:
            print("Callbacks found!" if self.callback_destinations else "No callbacks found!")

        # Now let's add the newly split blocks to self.split_blocks
        offset_buffer = []
        last_was_split = False
        for offset, block in self.code_blocks.items():
            if block.is_split:
                offset_buffer.append(offset)
            else:
                if last_was_split:
                    offset_buffer.append(offset)
                    self.split_blocks[offset_buffer[0]] = offset_buffer
                    offset_buffer = []

            last_was_split = block.is_split
        # This is kind of impossible, but let's throw a check anyway
        if offset_buffer:
            if self.verbose_level <= 3:
                print("The file ends with a split block!")
            self.split_blocks[offset_buffer[0]] = offset_buffer

    def apply_jump_table_to_blocks(self):
        if self.verbose_level <= 3:
            print("Step 1: conditional jumps...")
        self.apply_conditional_jumps()

        if self.verbose_level <= 3:
            print("Step 2: unconditional jumps...")
        self.apply_unconditional_jumps()

        if self.verbose_level <= 3:
            print("Step 3: cmd_inxJmp and switch-case tables...")
        self.apply_cmd_inxJmp()

        if self.verbose_level <= 3:
            print("Step 4: labels...")
        self.elementary_label_study()

        if self.verbose_level <= 3:
            print("Step 5: variable-jumping instructions...")
            print("Elementary:")

        self.elementary_runtime_jump_study()
        if self.verbose_level <= 3:
            print("Intermediate:")
        self.intermediate_runtime_jump_study()

        # Let's sort all "where_from" of our entry points
        self.sort_jumps_from()

    def write_to_file(self, output_path: Path):
        output = open(output_path, "w")
        for location, block in self.code_blocks.items():
            print(f"{location:08X} ",
                  f"Code block (number of instructions = {len(block.instructions)}, size = {block.size} bytes)",
                  file=output)

            print("Entry point", file=output, end="")
            if len(block.entry_points) == 1:
                print(" (single):", file=output)
            else:
                print("s (multiple):", file=output)

            for entry_point in block.entry_points.values():
                print(f"{entry_point.position:08X}", file=output, end="  ")
                print(f"0x{entry_point.instruction.signature:X} ({entry_point.instruction.name})", file=output, end="")
                if entry_point.where_from:
                    print(", jumps from:", file=output)
                else:
                    print("", file=output)  # this is EOL, don't worry

                for edge in entry_point.where_from:
                    exit_point = edge.exit
                    print(
                        f"- {exit_point.position:08X}".rjust(20),
                        f"0x{exit_point.instruction.signature:X}",
                        f"({exit_point.instruction.name})",
                        file=output
                    )
            print("Block instructions:", file=output)
            for offset, instruction in block.instructions.items():
                print(f"{offset:08X}  0x{instruction.signature:X} ({instruction.name})", file=output)
            print("", file=output)
        output.close()

    def normalize_entrypoints(self):
        if self.verbose_level <= 2:
            print("Step 8: normalizing entrypoints...")
        # I want to iterate iver the collection and modify it
        keys = list(self.code_blocks.keys())
        # Let's save the info about these blocks...
        for location in keys:
            code_block = self.code_blocks[location]

            if len(code_block.entry_points) == 1:
                continue
            # Now let's deal with this abnormality

            offsets = sorted(code_block.entry_points.keys())
            self.split_blocks[offsets[0]] = offsets

            end_location = location + code_block.size
            last_block = True
            for offset in offsets[:0:-1]:
                # Everything in [offset; end_location) is a new block
                new_block = ContiguousCodeBlock()
                new_block.size = end_location - offset
                new_block.start = offset

                instructions: Dict[int, PAC_instruction] = {}
                ordered_instructions: List[PAC_instruction] = []
                for instr_offset, instr in code_block.instructions.items():
                    if instr_offset < offset:
                        continue
                    instructions[instr_offset] = instr
                    ordered_instructions.append(instr)
                new_block.instructions = instructions
                new_block.ordered_instructions = ordered_instructions
                new_block.instructions_offsets = sorted(new_block.instructions.keys())

                # Now let's prepare the exitpoint
                new_block.exit_point.code_block = new_block
                new_block.exit_point.instruction = ordered_instructions[-1]
                new_block.exit_point.position = new_block.instructions_offsets[-1]

                # Reattach entry points to the new exitpoint
                edge: PAC_Edge
                for edge in code_block.exit_point.where_to:
                    new_block.exit_point.where_to.append(edge)
                    # edge.exit.where_to.remove(edge)
                    edge.exit = new_block.exit_point
                code_block.exit_point.where_to = []

                # Now let's shorten the current block
                code_block.size -= new_block.size
                shortened_instructions = {
                    instr_offset: code_block.instructions[instr_offset]
                    for instr_offset in sorted(set(code_block.instructions) - set(new_block.instructions))
                }
                code_block.instructions = shortened_instructions
                count = len(new_block.instructions_offsets)
                code_block.instructions_offsets = code_block.instructions_offsets[: -count]
                code_block.ordered_instructions = code_block.ordered_instructions[: -count]

                # Now let's modify the exitpoint
                code_block.exit_point.instruction = code_block.ordered_instructions[-1]
                code_block.exit_point.position = code_block.instructions_offsets[-1]

                # Now let's prepare the entry point
                entry_point = EntryPoint()
                entry_point.position = new_block.start
                entry_point.instruction = new_block.ordered_instructions[0]
                entry_point.code_block = new_block

                new_edge = PAC_Edge()
                # new_edge.properties = new_edge.properties._replace(save_address=False)  # Yeah, dataclasses...
                new_edge.exit = code_block.exit_point
                new_edge.entry = entry_point
                code_block.exit_point.where_to = [new_edge]

                # Two-step setup:
                entry_point.where_from = [new_edge]
                # ...but there could have been other jumps to this entry point:
                entry_point.where_from.extend(code_block.entry_points[offset].where_from)

                new_block.entry_points[new_block.start] = entry_point

                # Let's modify all edges which point to the old entry point
                for edge in code_block.entry_points[offset].where_from:
                    edge.entry = entry_point

                # Now let's delete this entry point
                del code_block.entry_points[offset]

                # new_block is ready to be deployed
                new_block.is_source = False
                self.code_blocks[new_block.start] = new_block
                end_location = new_block.start

                # And let's mark all the blocks as split besides the last one
                if last_block:
                    last_block = False
                else:
                    new_block.is_split = True
            code_block.is_split = True
            # After the block has been split, it could have become a source
            if not code_block.get_entry_point().where_from:
                code_block.is_source = True
        reordered_code_blocks: Dict[int, ContiguousCodeBlock] = {}
        keys = sorted(self.code_blocks.keys())
        for key in keys:
            reordered_code_blocks[key] = self.code_blocks[key]
        self.block_start_offsets = keys
        self.code_blocks = reordered_code_blocks
        self.sort_jumps_from()

