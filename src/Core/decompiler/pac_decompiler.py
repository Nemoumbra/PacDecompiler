
from typing import Callable, List, Dict, Tuple, NamedTuple, Set, Optional

from Core.decompiler.code_blocs.base_pac_code_blocks import (
    ContiguousCodeBlock, EntryPoint, PAC_Edge,
    ExitPoint, RawDataBlock
)
from Core.decompiler.code_blocs.pac_code_blocks import (
    PAC_CodeBlocks
)
from Core.decompiler.code_blocs.pac_function_blocks import (
    PAC_FunctionBlocks
)
from Utils.utils import (
    binary_search, read_shift_jis_from_bytes, print_hex
)
from Core.PAC.pac_file import (
    PAC_file, PAC_instruction
)

from dataclasses import dataclass, field

from pathlib import Path
import graphviz

# Resources
from Core.decompiler.decompiler_paths import *


def read_entity_hex(path: str) -> Dict[int, str]:
    id_to_name: Dict[int, str] = {}
    hex_id: str
    with open(path, encoding="utf-8") as file:
        for line in file:
            hex_id, name = line.strip().split(",")
            id_to_name[int(hex_id, 16)] = name
    return id_to_name


def read_jumping_instructions(path: str) -> Dict[int, int]:
    jumping_instr_info: Dict[int, int] = {}
    with open(path, encoding="utf-8") as file:
        for line in file:
            signature, arg_index = line.strip().split(" ")
            jumping_instr_info[int(signature, 16)] = int(arg_index)
    return jumping_instr_info


def read_returning_instructions(path: str) -> List[int]:
    returning_instr_info: List[int] = []
    with open(path, encoding="utf-8") as file:
        for line in file:
            signature = line.strip()
            returning_instr_info.append(int(signature, 16))
    return returning_instr_info


class GVSettings(NamedTuple):
    fontsize: int
    nslimit: Optional[int]


class PAC_Subroutine:
    pass


class PAC_DataBlocks:
    def __init__(self, file: Optional[PAC_file] = None):
        self.file: PAC_file = file if file is not None else PAC_file()
        self.data_blocks: Dict[int, RawDataBlock] = {}
        self.block_start_offsets: List[int] = []

    def reset(self, file: PAC_file):
        self.file = file
        self.data_blocks = {}
        self.block_start_offsets = []

    def init_blocks(self):
        for location, entity in self.file.raw_entities.items():
            data_block = RawDataBlock()
            data_block.start = location
            data_block.data = entity.raw_data
            data_block.size = entity.size
            try:
                data_block.shift_jis = read_shift_jis_from_bytes(entity.raw_data, 0, entity.size)
            except UnicodeDecodeError:
                pass

            self.data_blocks[location] = data_block

        self.block_start_offsets = sorted(self.data_blocks.keys())

    def get_block_by_offset(self, offset: int):
        """
            This function returns the block which contains the offset\n
            If there is none, it returns None\n
            :param offset: the offset to look for
            :return: either None or a tuple of the real start offset and the block
        """
        if offset < 0:
            raise ValueError("Offset must be non-negative")

        index = binary_search(self.block_start_offsets, offset)
        if index == -1:
            return None

        block_start = self.block_start_offsets[index]
        block = self.data_blocks[block_start]
        if offset < block_start + block.size:
            # Offset belongs to this block
            return block_start, block

        # It's not within any blocks
        return None


class PAC_Functions:
    def __init__(self, file: Optional[PAC_file] = None):
        self.file: PAC_file = file if file is not None else PAC_file()
        self.functions: Dict[int, PAC_Subroutine] = {}
        self.code_blocks: PAC_FunctionBlocks = PAC_FunctionBlocks()
        self.entry_points: List[int] = []

        # self.saving_RA_instructions: Set[int] = set()

    def reset(self, file: PAC_file):
        self.file = file
        self.code_blocks.reset(file)

    # def set_instructions_info(self, saving_RA: Set[int]):
    #     self.saving_RA_instructions = saving_RA


class PAC_StackFrame:
    def __init__(self, RA):
        self.RA = RA


SkipCriterion = Callable[[int], bool]


def skip_if_equal(color: int) -> SkipCriterion:
    return lambda vertex_color: vertex_color == color


def skip_if_not_equal(color: int) -> SkipCriterion:
    return lambda vertex_color: vertex_color != color


def print_all() -> SkipCriterion:
    return lambda vertex_color: False


def print_reached() -> SkipCriterion:
    return lambda vertex_color: vertex_color == 0


class OrdinaryGraph:
    def __init__(self):
        self.graph: List[Set[int]] = []
        self.color: List[int] = []
        self.parent: List[int] = []
        self.tin: List[int] = []
        self.tout: List[int] = []
        self.timer: int = 0
        self.topsort: List[int] = []
        self.size: int = 0

    def reset_color(self):
        self.color = [0] * self.size

    def prepare_lists(self):
        self.reset_color()
        self.parent = [0] * self.size
        self.tin = [0] * self.size
        self.tout = [0] * self.size

    def DFS(self, v: int, p: int = -1):
        self.color[v] = -1
        self.parent[v] = p
        self.tin[v] = self.timer
        self.timer += 1
        for to in self.graph[v]:
            if self.color[to] == 0:
                self.DFS(to, v)
        self.tout[v] = self.timer
        self.timer += 1
        self.color[v] = 2

    def topsort_DFS(self, v: int):
        self.color[v] = -1
        for to in self.graph[v]:
            if self.color[to] == 0:
                self.topsort_DFS(to)
        self.topsort.append(v)
        self.color[v] = 2

    def compute_topsort(self):
        for i in range(self.size):
            if self.color[i] == 0:
                self.topsort_DFS(i)


class CondensedGraph:
    def __init__(self, graph: OrdinaryGraph, to_root_node: List[int], root_nodes: List[int]):
        self.data = graph
        self.to_root_node = to_root_node
        self.roots = root_nodes
        pass


def edge_to_color_style(edge: PAC_Edge):
    if edge.properties.callback:
        return "orange", "solid"
    if edge.properties.special:
        return "violet", "solid"
    if edge.properties.potential:
        return "black", "dotted"
    if edge.exit.code_block.is_split:
        return "blue", "solid"
    if edge.properties.save_address:
        return "green", "solid"
    if edge.properties.fallthrough:
        return "black", "dashed"
    return "black", "solid"


def block_to_color(block: ContiguousCodeBlock, vertex: int, roots: Dict[int, None], matched: Set[int]):
    if block.start in matched:
        return "green"

    if block.is_source:
        # Or is it?
        is_source = False
        for edge in block.exit_point.where_to:
            if not edge.properties.special:
                # Ok, now we believe it is a real source
                is_source = True
                break

        if is_source:
            # source node
            return "yellow"

        # Isolated node or the one that ends with doSelect
        return "red"

    # Node is not a source
    is_sink = True
    for edge in block.exit_point.where_to:
        if not edge.properties.special:
            # Just a normal node
            is_sink = False
            break
    if is_sink:
        # Sink node
        return "violet"

    # Maybe this node is a part of the graph's base?
    if vertex in roots:
        return "yellow"

    return "white"


class PAC_Visitor:
    def __init__(self, pac_code: PAC_CodeBlocks):

        # self.PC = entry.position
        self.stack: List[PAC_StackFrame] = []
        # self.current_block = entry.code_block
        self.all_code = pac_code
        self.matched: Set[int] = set()

        self.ignore_callbacks = True
        self.ignore_special = True
        self.warning_imperfect_block_start = False

        self.size: int = len(pac_code.block_start_offsets)
        self.edges_count: int = 0
        self.offset_to_index: Dict[int, int] = {offset: i for i, offset in enumerate(pac_code.block_start_offsets)}
        self.color: List[int] = [0] * self.size
        self.parent: List[int] = [0] * self.size
        self.tin: List[int] = [0] * self.size
        self.tout: List[int] = [0] * self.size
        self.timer: int = 0
        self.topsort: List[int] = []
        self.is_DAG = True
        self.multiple_entrypoint_loops: List[int] = []

        self.components_buffer: List[int] = []
        self.non_trivial_components: Dict[int, Set[int]] = {}
        self.condensed: Optional[CondensedGraph] = None
        self.belongs_to_cycle: List[bool] = []
        self.dominator_tree: Optional[OrdinaryGraph] = None

        self.isolated: List[int] = []
        self.sources: List[int] = []
        self.sinks: List[int] = []
        self.roots: Dict[int, None] = {}  # simulating an ordered set
        pass

    def set_matched_blocks(self, matched: Set[int]):
        self.matched = matched

    def declare_dot_nodes(self, dot: graphviz.Digraph, skip: SkipCriterion):
        for address, block in self.all_code.code_blocks.items():
            # Maybe we should skip it?
            vertex = self.offset_to_index[address]

            if skip(self.color[vertex]):
                continue

            node_text = block.to_dot_str()

            color = block_to_color(block, vertex, self.roots, self.matched)

            dot.node(f"{address}", node_text, fillcolor=color)

    def declare_dot_edges(self, dot: graphviz.Digraph, skip: SkipCriterion):
        for address, block in self.all_code.code_blocks.items():
            # Maybe we should skip it?
            vertex = self.offset_to_index[address]
            # if self.color[vertex] == 0:
            #     continue
            if skip(self.color[vertex]):
                continue

            for entry_point in block.entry_points.values():
                for edge in entry_point.where_from:
                    # maybe some edges go from the non-existent blocks?
                    from_block = edge.exit.code_block
                    parent = self.offset_to_index[from_block.start]
                    # if self.color[parent] == 0:
                    #     continue
                    if skip(self.color[parent]):
                        continue

                    color, style = edge_to_color_style(edge)

                    dot.edge(f"{from_block.start}", f"{address}", color=color, style=style)
                    # Add ,tailport="s", headport="n" to make a "forced" version of the graph

    def declare_dot_SCC_subgraphs(self, dot: graphviz.Digraph, skip: SkipCriterion, settings: GVSettings):
        for color_id, vertices in self.non_trivial_components.items():
            subgraph = graphviz.Digraph(
                node_attr={
                    "fontname": "courier",
                    "fontsize": f"{settings.fontsize}",
                    "shape": "box",
                    "colorscheme": "paired6",
                    "style": "filled"
                },
                edge_attr={"fontname": "courier"},
                graph_attr={"bgcolor": "grey"},
                name=f"cluster_color_{color_id}"
            )
            for v in vertices:
                # Maybe we should skip it?
                if skip(self.color[v]):
                    continue
                offset = self.all_code.block_start_offsets[v]
                subgraph.node(f"{offset}")
            dot.subgraph(subgraph)

    def declare_dot_fallthrough_subgraphs(self, dot: graphviz.Digraph, skip: SkipCriterion, settings: GVSettings):
        for start_offset, offsets in self.all_code.split_blocks.items():
            # Let's see if it is even worth declaring a subgraph

            # Note: the list "offsets" is in an ascending order which means
            # that fallthrough arrows come from offsets[i] to offsets[i+1].
            # Sequence {self.belongs_to_cycle[offset]} is also ascending (example: 00000111)

            # Note: using binary search here is superfluous.
            start = self.offset_to_index[start_offset]

            first_cycle_vertex = -1
            for offset in offsets:
                vertex = self.offset_to_index[offset]
                if self.belongs_to_cycle and self.belongs_to_cycle[vertex]:
                    first_cycle_vertex = vertex
                    break

            if first_cycle_vertex == start:
                # The whole chain lies inside the 'SCC containing v'
                continue

            if first_cycle_vertex == -1:
                first_cycle_vertex = self.offset_to_index[offsets[-1]] + 1

            if start == first_cycle_vertex - 1:
                # Only one node left out
                continue

            subgraph = graphviz.Digraph(
                node_attr={
                    "fontname": "courier",
                    "fontsize": f"{settings.fontsize}",
                    "shape": "box",
                    "colorscheme": "paired6",
                    # "style": "dashed"
                },
                edge_attr={"fontname": "courier"},
                graph_attr={
                    # "bgcolor": "grey"
                    "style": "dotted"
                },
                name=f"cluster_{start_offset:X}"
            )

            for v in range(start, first_cycle_vertex):
                if skip(self.color[v]):
                    continue
                subgraph.node(f"{self.all_code.block_start_offsets[v]}")

            dot.subgraph(subgraph)

    def make_dot_file(self, name_suffix: str, dir_path: Path, settings: GVSettings, skip: SkipCriterion):
        dot = graphviz.Digraph(
            node_attr={
                "fontname": "courier",
                "fontsize": f"{settings.fontsize}",
                "shape": "box",
                "colorscheme": "paired6",
                "style": "filled"
            },
            edge_attr={"fontname": "courier"},
        )
        if settings.nslimit is not None:
            dot.graph_attr["nslimit"] = f"{settings.nslimit}"

        # Declare the nodes
        self.declare_dot_nodes(dot, skip)

        # Declare the edges
        self.declare_dot_edges(dot, skip)

        # Declare the subgraphs for the non-trivial components
        self.declare_dot_SCC_subgraphs(dot, skip, settings)

        # Try to group the split blocks together
        self.declare_dot_fallthrough_subgraphs(dot, skip, settings)

        new_name = self.all_code.file.name + "_" + name_suffix
        suffix = (dir_path / new_name).suffix
        file_path = (dir_path / new_name).with_suffix(suffix + ".gv")  # Looks a little ugly
        with open(file_path, "w") as dot_output:
            dot_output.write(dot.source)

        new_path = file_path.with_suffix(".svg")
        # print(f"dot -Tsvg {file_path} -o {new_path}")
        return f"dot -Tsvg {file_path} -o {new_path}"

    def reset_color(self):
        self.color = [0] * self.size

    def DFS(self, vertex: EntryPoint, color: int, parent: Optional[ExitPoint] = None, *, maxdepth: int = -1):
        if maxdepth == 0:
            # As if the parent DFS didn't even go here
            return 0, 0

        v = self.offset_to_index[vertex.position]
        self.tin[v] = self.timer
        self.timer += 1
        if parent is None:
            p = -1
        else:
            p = self.offset_to_index[parent.code_block.start]
        self.parent[v] = p
        self.color[v] = -1
        exitpoint = vertex.code_block.exit_point

        depth, size = 1, 1

        if maxdepth != -1:
            maxdepth -= 1
        for edge in exitpoint.where_to:
            if self.ignore_callbacks and edge.properties.callback:
                continue
            if self.ignore_special and edge.properties.special:
                continue
            to = self.offset_to_index[edge.entry.position]
            if self.color[to] == 0:
                subdepth, subsize = self.DFS(edge.entry, color, exitpoint, maxdepth=maxdepth)
                depth = max(depth, subdepth + 1)
                size += subsize

        self.tout[v] = self.timer
        self.timer += 1
        self.color[v] = color
        return depth, size

    def reverse_DFS(self, vertex: ExitPoint, color: int, make_component: bool = False, *, maxdepth: int = -1):
        if maxdepth == 0:
            # As if the parent DFS didn't even go here
            return 0, 0

        v = self.offset_to_index[vertex.code_block.start]
        self.color[v] = color
        size, depth = 1, 1
        # Fill the buffer with reached nodes
        if make_component:
            self.components_buffer.append(v)

        entry_point = vertex.code_block.get_entry_point()

        if maxdepth != -1:
            maxdepth -= 1
        for edge in entry_point.where_from:
            if self.ignore_callbacks and edge.properties.callback:
                continue
            if self.ignore_special and edge.properties.special:
                continue
            from_vertex = self.offset_to_index[edge.exit.code_block.start]
            if self.color[from_vertex] == 0:
                subtree_size, subtree_depth = self.reverse_DFS(edge.exit, color, make_component, maxdepth=maxdepth)
                size += subtree_size
                depth = max(depth, subtree_depth + 1)
        return size, depth

    def find_reachable(self, offset: int, color: int = 2, *, maxdepth: int = -1):
        if self.warning_imperfect_block_start:
            if offset not in self.all_code.code_blocks:
                print(f"The offset 0x{offset:X} does not correspond to any of the blocks!")
                return False
        res = self.all_code.get_block_by_offset(offset)
        if res is None:
            print(f"The offset 0x{offset:X} does not correspond to any of the blocks!")
            return False
        _, code_block = res
        entry_point = code_block.get_entry_point()

        depth, size = self.DFS(entry_point, color, maxdepth=maxdepth)
        return True

    def find_reachable_from(self, offsets: List[int], *, maxdepth: int = -1):
        # No checks made beforehand
        self.reset_color()
        for i, offset in enumerate(offsets):
            if not self.find_reachable(offset, i+1, maxdepth=maxdepth):
                print(f"The offset 0x{offset:X} does not correspond to any of the blocks!")

    def find_parents(self, offset: int, color: int = 1, *, maxdepth: int = -1):
        if self.warning_imperfect_block_start:
            if offset not in self.all_code.code_blocks:
                print(f"The offset 0x{offset:X} does not correspond to any of the blocks!")
                return False
        res = self.all_code.get_block_by_offset(offset)
        if res is None:
            print(f"The offset 0x{offset:X} does not correspond to any of the blocks!")
            return False
        _, code_block = res

        depth, size = self.reverse_DFS(code_block.exit_point, color, maxdepth=maxdepth)

        return True

    def find_parents_of(self, offsets: List[int], *, maxdepth: int = -1):
        # No checks made beforehand
        self.reset_color()
        for i, offset in enumerate(offsets):
            if not self.find_parents(offset, i+1, maxdepth=maxdepth):
                print(f"The offset 0x{offset:X} does not correspond to any of the blocks!")

    def topsort_DFS(self, vertex: EntryPoint, color: int):
        v = self.offset_to_index[vertex.position]
        self.color[v] = -1
        exitpoint = vertex.code_block.exit_point
        # found_cycle = False
        for edge in exitpoint.where_to:
            if self.ignore_callbacks and edge.properties.callback:
                continue
            if self.ignore_special and edge.properties.special:
                continue
            to = self.offset_to_index[edge.entry.position]
            if self.color[to] == -1:
                # found_cycle = True
                self.is_DAG = False
                continue  # technically we can comment this line out
            if self.color[to] == 0:
                # found_cycle = self.topsort_DFS(edge.entry, color) or found_cycle
                self.topsort_DFS(edge.entry, color)

        self.topsort.append(v)
        # self.tout[v] = self.timer
        # self.timer += 1
        self.color[v] = color
        # print(f"Exiting 0x{vertex.position:X}")
        # return found_cycle

    def compute_topsort(self):
        for i in range(self.size):
            if self.color[i] == 0:
                offset = self.all_code.block_start_offsets[i]
                entry_point = self.all_code.code_blocks[offset].get_entry_point()
                self.topsort_DFS(entry_point, 1)
        return self.is_DAG

    def kosaraju_algorithm(self, make_condensed: bool = False):
        self.reset_color()
        non_trivial_components: Set[Tuple[int, int]] = set()
        condensed = OrdinaryGraph()
        # Mapping is a list which maps indexes in graph to indexes in the condensed graph
        to_root_node: List[int] = [-1] * self.size

        # root nodes is a subset of graph vertices: every SCC contains exactly one representative node
        # (So if v comes from root_nodes, then to_root_node[v] gives you the condensed graph node index
        root_nodes: List[int] = []
        condensed.graph = [set() for _ in range(self.size)]

        for i, v in enumerate(reversed(self.topsort)):
            if self.color[v] == 0:
                offset = self.all_code.block_start_offsets[v]
                exit_point = self.all_code.code_blocks[offset].exit_point
                color = i + 1
                count, _ = self.reverse_DFS(exit_point, color, make_condensed)
                # Don't forget to memorize non-trivial components
                if count > 1:
                    non_trivial_components.add((color, count))

                if make_condensed:
                    # v will be a 'root' vertex of the SCC in the buffer
                    for vertex in self.components_buffer:
                        to_root_node[vertex] = v
                    root_nodes.append(v)
                    # clear the buffer
                    self.components_buffer = []

        # (There's a hack: to_root_node[v] comes from a set of original graph's indexes)
        # Let's add edges to the condensed graph
        if make_condensed:
            for address, block in self.all_code.code_blocks.items():
                v = self.offset_to_index[address]
                for edge in block.exit_point.where_to:
                    to = self.offset_to_index[edge.entry.position]
                    if to_root_node[v] != to_root_node[to]:
                        # Different SCC => let's make an edge
                        condensed.graph[to_root_node[v]].add(to_root_node[to])

            self.condensed = CondensedGraph(condensed, to_root_node, root_nodes)
            # That's a lil deceiving
            self.condensed.data.size = self.size

        return non_trivial_components

    def find_components(self, condense: bool = False):
        components_info = self.kosaraju_algorithm(condense)
        colors = set((color for color, _ in components_info))
        self.belongs_to_cycle = [False] * self.size
        self.non_trivial_components = {color: set() for color, _ in components_info}
        for i, color in enumerate(self.color):
            if color in colors:
                self.non_trivial_components[color].add(i)
                self.belongs_to_cycle[i] = True

    def compute_sources_sinks(self):
        for address, block in self.all_code.code_blocks.items():
            if block.is_source:
                v = self.offset_to_index[address]

                if block.exit_point.where_to:
                    self.sources.append(v)
                else:
                    self.isolated.append(v)
            elif not block.exit_point.where_to:
                v = self.offset_to_index[address]
                self.sinks.append(v)

    def find_roots(self):
        pass
        # self.roots.extend(self.isolated)
        # self.roots.extend(self.sources)
        # self.color = [0] * len(self.color)
        # for source in self.sources:
        #     self.find_reachable(self.all_code.block_start_offsets[source])
        # some SSC could have left
        # for vertices in self.non_trivial_components.values():
        #     v = next(iter(vertices))
        #     if self.color[v] == 0:
        #         # This component needs
        #         pass
        #     pass
        pass
        if self.is_DAG:
            # This case is easier
            self.roots.update({v: None for v in self.isolated})
            self.roots.update({v: None for v in self.sources})
        else:
            # But here we make a topsort of the condensed graph
            self.condensed.data.prepare_lists()
            self.condensed.data.compute_topsort()
            self.condensed.data.reset_color()
            condensed_roots = []
            hashed = set(self.condensed.roots)
            vertices = [v for v in reversed(self.condensed.data.topsort) if v in hashed]
            for v in vertices:
                if self.condensed.data.color[v] == 0:
                    condensed_roots.append(v)
                    # if self.all_code.block_start_offsets[v] == 0x1C:
                    #     print("Found")
                    self.condensed.data.DFS(v)
            # Now condensed_roots is a subset of condensed.root_nodes
            self.roots.update({v: None for v in condensed_roots})
        pass

    def count_edges(self):
        self.edges_count = 0
        for block in self.all_code.code_blocks.values():
            self.edges_count += len(block.get_outgoing()) + len(block.get_incoming())
        self.edges_count //= 2

    def build_dominator_tree(self):
        pass


@dataclass
class DecompilerSettings:
    DFS_ignore_callbacks: bool = True
    DSF_ignore_special_edges: bool = True
    visitor_imperfect_block_start_warning: bool = False
    verbose_level: int = 2
    include_callbacks: bool = True
    make_dot_file: bool = True
    dot_settings: GVSettings = GVSettings(fontsize=10, nslimit=12)
    default_dot_name_suffix: str = "svg"
    SVG_path: str = ""


@dataclass
class PAC_stats:
    use_IntLocals: Dict[int, Dict[int, PAC_instruction]] = field(default_factory=dict)
    use_FloatLocals: Dict[int, Dict[int, PAC_instruction]] = field(default_factory=dict)
    use_IntGlobals: Dict[int, Dict[int, PAC_instruction]] = field(default_factory=dict)
    use_FloatGlobals: Dict[int, Dict[int, PAC_instruction]] = field(default_factory=dict)
    use_IntConstants: Dict[int, Dict[int, PAC_instruction]] = field(default_factory=dict)
    use_FloatConstants: Dict[int, Dict[int, PAC_instruction]] = field(default_factory=dict)
    use_0x1_values: Dict[int, Dict[int, PAC_instruction]] = field(default_factory=dict)
    use_4_byte_values: Dict[int, Dict[int, PAC_instruction]] = field(default_factory=dict)
    use_flags: Dict[int, Dict[int, PAC_instruction]] = field(default_factory=dict)


class PAC_Decompiler:
    def __init__(self):
        self.file: PAC_file = PAC_file()
        self.code: PAC_CodeBlocks = PAC_CodeBlocks()
        self.data: PAC_DataBlocks = PAC_DataBlocks()
        self.functions: PAC_Functions = PAC_Functions()
        self.settings = DecompilerSettings()
        self.stats = PAC_stats()
        self.CFG_visitor: Optional[PAC_Visitor] = None
        self.console_dot_command: str = ""
        self.matched_offsets: Set[int] = set()

    def setResources(self, signature_to_name: Optional[Dict[int, str]] = None):
        self.code.read_instructions_info(
            cond_jump_instructions_path,
            uncond_jump_instructions_path,
            jumping_instructions_path,
            returning_instructions_path,
            saving_instructions_path,
            callback_instructions_path
        )
        self.code.read_important_signatures(important_instructions_path)
        if signature_to_name is not None:
            self.code.set_signature_to_name(signature_to_name)

    def reset(self, file: PAC_file):
        self.file = file
        self.code.reset(self.file)
        self.data.reset(self.file)
        self.functions.reset(self.file)

    def gather_stats(self):
        stats = PAC_stats()

        def update_stats():
            # Variables
            for var in sorted(used_vars.var_0x4):
                if var not in stats.use_IntLocals:
                    stats.use_IntLocals[var] = {}
                stats.use_IntLocals[var][location] = instruction

            for var in sorted(used_vars.var_0x20):
                if var not in stats.use_FloatLocals:
                    stats.use_FloatLocals[var] = {}
                stats.use_FloatLocals[var][location] = instruction

            for var in sorted(used_vars.var_0x8):
                if var not in stats.use_IntGlobals:
                    stats.use_IntGlobals[var] = {}
                stats.use_IntGlobals[var][location] = instruction

            for var in sorted(used_vars.var_0x40):
                if var not in stats.use_FloatGlobals:
                    stats.use_FloatGlobals[var] = {}
                stats.use_FloatGlobals[var][location] = instruction

            # Constants
            for value in sorted(used_consts.const_0x2):
                if value not in stats.use_IntConstants:
                    stats.use_IntConstants[value] = {}
                stats.use_IntConstants[value][location] = instruction

            for value in sorted(used_consts.const_0x10):
                if value not in stats.use_FloatConstants:
                    stats.use_FloatConstants[value] = {}
                stats.use_FloatConstants[value][location] = instruction

            # 0x1 values
            for value in sorted(_0x1_values):
                if value not in stats.use_0x1_values:
                    stats.use_0x1_values[value] = {}
                stats.use_0x1_values[value][location] = instruction

            # 4 byte values
            for value in sorted(used_4_byte_values):
                if value not in stats.use_4_byte_values:
                    stats.use_4_byte_values[value] = {}
                stats.use_4_byte_values[value][location] = instruction

        for location, instruction in self.file.ordered_instructions.items():
            used_vars = instruction.get_used_pac_vars()
            _0x1_values = instruction.get_used_0x1_values()
            used_consts = instruction.get_used_constants()
            used_4_byte_values = instruction.get_used_4_byte_values()
            update_stats()

        # Here we may do something about the flags, but it's much harder
        self.stats = stats

    def aggressive_label_cracker(self):
        if self.settings.verbose_level <= 2:
            print("Aggressive label cracker launched...")
        # Reserved for cracking 4:0 runtime labels

        # Let's find all setGateInfo instructions that fit our case
        instructions = self.file.getInstructions(0x2516bd00)
        instructions = {
            offset: instr
            for offset, instr in instructions.items()
            if instr.ordered_PAC_params[-1][0].type.startswith("0x1")
        }

        # This struct maps instruction locations to the values of relevant args
        setGateInfoOffsets = {}
        for location, instruction in instructions.items():
            last_arg = instruction.ordered_PAC_params[-1]
            before_the_last_arg = instruction.ordered_PAC_params[-2]
            if before_the_last_arg[0].type != "uint32_t":
                if self.settings.verbose_level <= 2:
                    print(f"The 3rd argument of setGateInfo at {location:X} is not an integer!")
                continue

            setGateInfoOffsets[location] = before_the_last_arg[1], last_arg[1]

        if self.settings.verbose_level <= 2:
            print(f"{setGateInfoOffsets=}")
            print_hex(list(setGateInfoOffsets.keys()))

        # Now let's see if the destinations correspond to the start offsets of the blocks
        destinations = {args[-1] for args in setGateInfoOffsets.values()}
        current_destinations = set(self.code.code_blocks.keys())
        difference = destinations - current_destinations
        if not difference:
            # They do! We don't have to split blocks any more!
            pass
        else:
            # We have to split some more blocks... If the destinations are valid, of course
            print("WARNING, deduced new code block starts! Not implemented => aborting!")
            raise RuntimeError

        # Now let's see which blocks are reachable by the values set by setGateInfo
        visitor = PAC_Visitor(self.code)

        # vertices = {visitor.offset_to_index[offset] for offset in self.code.getGateInfo_jumps}
        def test_this_setGateInfo(start: ContiguousCodeBlock, args):
            visitor.reset_color()

            def special_DFS(entrypoint: EntryPoint):
                v = visitor.offset_to_index[entrypoint.position]
                visitor.color[v] = -1
                for edge in entrypoint.code_block.get_outgoing():
                    to_offset = edge.entry.position
                    to = visitor.offset_to_index[to_offset]
                    if visitor.color[to] == 0:
                        if to_offset in setGateInfoOffsets:
                            # We don't want to go there...
                            continue
                        if to_offset in self.code.getGateInfo_block_offsets:
                            # Good! We've reached the block with cmd_jmp/callLabel!
                            _, block = self.code.get_block_by_offset(to_offset)
                            if not hasattr(block, "dataflow_input"):
                                block.dataflow_input = set()
                            block.dataflow_input.add(args)
                            continue
                        special_DFS(edge.entry)

            special_DFS(start.get_entry_point())

        for offset, args in setGateInfoOffsets.items():
            _, start_block = self.code.get_block_by_offset(offset)
            test_this_setGateInfo(start_block, args)
            pass

        #     visitor.color[v] = 2

        pass

    def make_IR(self):
        self.code.break_into_blocks(self.settings.include_callbacks)
        self.code.apply_jump_table_to_blocks()
        self.code.apply_returning_instructions()
        if self.settings.include_callbacks:
            self.code.apply_callbacks()
        self.aggressive_label_cracker()
        self.code.normalize_entrypoints()

    def setMatchedOffsets(self, matched: Set[int]):
        self.matched_offsets = matched

    def make_dot_file(self):
        self.CFG_visitor.set_matched_blocks(self.matched_offsets)
        return self.CFG_visitor.make_dot_file(
            self.settings.default_dot_name_suffix,
            Path(self.settings.SVG_path),
            self.settings.dot_settings,
            print_all()
        )

    def analyze_data(self):
        self.data.init_blocks()
        if not self.data.data_blocks:
            return

        for location, instruction in self.file.ordered_instructions.items():
            _0x1_values = instruction.get_used_0x1_values()
            _4byte_values = instruction.get_used_4_byte_values()

            total = set(_0x1_values).union(_4byte_values)
            if not total:
                continue

            for value in total:
                res = self.data.get_block_by_offset(value)
                if res is None:
                    continue
                real_offset, block = res
                if real_offset == value:
                    block.references_from[location] = instruction
                else:
                    if self.settings.verbose_level <= 2:
                        print(f"Possible reference from 0x{location:X} to 0x{real_offset:X}")

    def study_CFG(self):
        visitor = PAC_Visitor(self.code)
        visitor.ignore_special = self.settings.DSF_ignore_special_edges
        visitor.ignore_callbacks = self.settings.DFS_ignore_callbacks
        visitor.warning_imperfect_block_start = self.settings.visitor_imperfect_block_start_warning

        visitor.compute_sources_sinks()
        if self.settings.verbose_level <= 2:
            print(f"{visitor.size=}, {len(visitor.sources)=}, {len(visitor.sinks)=}, {len(visitor.isolated)=}")

        visitor.count_edges()
        if self.settings.verbose_level <= 2:
            print(f"{visitor.edges_count=}")
            print(f"Density = {visitor.edges_count / (visitor.size * (visitor.size - 1))}")

        is_DAG = visitor.compute_topsort()
        if self.settings.verbose_level <= 2:
            print(f"The graph is " + ("" if is_DAG else "not ") + "a DAG!")
        if not is_DAG:
            if self.settings.verbose_level <= 2:
                print("Launching the Kosaraju algorithm...")
            visitor.find_components(True)
            # print non-trivial components
            for i, vertices in enumerate(visitor.non_trivial_components.values()):
                if self.settings.verbose_level <= 2:
                    print(f"Component {i}")
                offsets: List[int] = []
                for v in vertices:
                    offset = self.code.block_start_offsets[v]
                    offsets.append(offset)
                if self.settings.verbose_level <= 2:
                    print(", ".join([f"0x{offset:X}" for offset in offsets]))

        if self.settings.verbose_level <= 2:
            print("Starting flowgraph roots search")
        visitor.find_roots()

        # print(", ".join([f"0x{visitor.all_code.block_start_offsets[v]:X}" for v in visitor.roots]))
        sources = set(visitor.sources)
        isolated = set(visitor.isolated)
        # difference_1 = set(visitor.roots) - isolated
        non_trivial_roots = (set(visitor.roots) - isolated) - sources
        if self.settings.verbose_level <= 2:
            print(f"Found {len(non_trivial_roots)} non trivial roots")
            print(", ".join([f"0x{visitor.all_code.block_start_offsets[v]:X}" for v in non_trivial_roots]))
            print(f"Total count = {len(visitor.roots)}")
        if self.settings.verbose_level <= 2:
            print(
                "Cyclomatic number (using flowroots) =",
                f"{visitor.edges_count - visitor.size + 2 + len(visitor.roots)}",
                ", (without components) =",
                f"{visitor.edges_count - visitor.size + 2}",
            )

        # Examine loop entrypoints
        next_component = False
        for i, vertices in enumerate(visitor.non_trivial_components.values()):
            found_one = False
            next_component = False
            for vertex in vertices:
                offset = self.code.block_start_offsets[vertex]
                block = self.code.code_blocks[offset]
                for edge in block.get_incoming():
                    v = visitor.offset_to_index[edge.exit.code_block.start]
                    if v not in vertices:
                        if found_one:
                            # Not the first time we've entered that if before
                            if self.settings.verbose_level <= 2:
                                print(f"Component {i} has multiple entrypoints!")
                                visitor.multiple_entrypoint_loops.append(i)
                            next_component = True
                        found_one = True
                        break

                if next_component:
                    break
                if self.settings.verbose_level <= 1 and not found_one:
                    print(f"Component {i} contains a non-trivial flowgraph root.")

        if self.settings.verbose_level <= 2 and not next_component:
            print("Every loop has no more than one entrypoint!")
        # Kind of done...
        self.CFG_visitor = visitor

    def create_functions(self):
        self.functions.code_blocks.break_into_blocks(self.code)

    def decompile(self, settings: DecompilerSettings):
        self.settings = settings
        self.code.verbose_level = self.settings.verbose_level
        self.functions.code_blocks.verbose_level = self.settings.verbose_level

        self.gather_stats()
        self.make_IR()
        self.analyze_data()
        self.study_CFG()
        self.create_functions()
        if settings.make_dot_file:
            self.console_dot_command = self.make_dot_file()

    def draw_reachable(self, offsets: Set[int], *, name: str = "", maxdepth: int = -1):
        self.CFG_visitor.find_reachable_from(list(offsets), maxdepth=maxdepth)
        return self.CFG_visitor.make_dot_file(
            self.settings.default_dot_name_suffix if not name else name,
            Path(self.settings.SVG_path),
            self.settings.dot_settings,
            print_reached()
        )

    def draw_parents(self, offsets: Set[int], *, name: str = "", maxdepth: int = -1):
        self.CFG_visitor.find_parents_of(list(offsets), maxdepth=maxdepth)
        return self.CFG_visitor.make_dot_file(
            self.settings.default_dot_name_suffix if not name else name,
            Path(self.settings.SVG_path),
            self.settings.dot_settings,
            print_reached()
        )
