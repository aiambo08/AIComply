"""
AIComply - Intra-Procedural Control Flow Graph (CFG) Builder
Construye grafos de flujo de control para funciones y bloques de código,
identificando bifurcaciones y puntos de unión phi para análisis de taint.
"""

import ast
from typing import List, Optional, Set


class CFGNode:
    """Nodo en el Grafo de Control de Flujo."""

    def __init__(
        self, node_id: int, ast_node: Optional[ast.AST], label: str = ""
    ) -> None:
        self.node_id = node_id
        self.ast_node = ast_node
        self.label = label
        self.predecessors: List["CFGNode"] = []
        self.successors: List["CFGNode"] = []
        self.is_phi: bool = False
        self.is_branch_condition: bool = False
        self.branch_condition_ast: Optional[ast.AST] = None
        self.is_human_gate: bool = False

    def add_successor(self, succ: "CFGNode") -> None:
        if succ not in self.successors:
            self.successors.append(succ)
        if self not in succ.predecessors:
            succ.predecessors.append(self)

    def __repr__(self) -> str:
        return f"CFGNode({self.node_id}, label='{self.label}', phi={self.is_phi})"


class ControlFlowGraph:
    """Grafo de Control de Flujo de una función o bloque."""

    def __init__(
        self, name: str, entry: CFGNode, exit_node: CFGNode, nodes: List[CFGNode]
    ) -> None:
        self.name = name
        self.entry = entry
        self.exit_node = exit_node
        self.nodes = nodes

    def get_topological_order(self) -> List[CFGNode]:
        """Retorna los nodos en orden aproximado de ejecución topológica."""
        visited: Set[int] = set()
        order: List[CFGNode] = []

        stack = [(self.entry, False)]
        while stack:
            curr, expanded = stack.pop()
            if expanded:
                order.append(curr)
            elif curr.node_id not in visited:
                visited.add(curr.node_id)
                stack.append((curr, True))
                stack.extend((succ, False) for succ in reversed(curr.successors))
        order.reverse()
        return order


class CFGBuilder:
    """Generador de Grafos de Control de Flujo a partir del AST de Python."""

    def __init__(self) -> None:
        self._next_id = 0

    def _create_node(self, ast_node: Optional[ast.AST], label: str = "") -> CFGNode:
        node = CFGNode(self._next_id, ast_node, label=label)
        self._next_id += 1
        return node

    def build_for_function(
        self, func_def: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> ControlFlowGraph:
        """Construye el CFG para una definición de función."""
        entry = self._create_node(None, label=f"ENTRY: {func_def.name}")
        exit_node = self._create_node(None, label=f"EXIT: {func_def.name}")
        all_nodes = [entry, exit_node]

        last_node = self._build_block(func_def.body, entry, exit_node, all_nodes)
        last_node.add_successor(exit_node)

        return ControlFlowGraph(func_def.name, entry, exit_node, all_nodes)

    def build_for_module(self, module: ast.Module) -> ControlFlowGraph:
        """Construye el CFG para el nivel de módulo principal."""
        entry = self._create_node(None, label="ENTRY: module")
        exit_node = self._create_node(None, label="EXIT: module")
        all_nodes = [entry, exit_node]

        last_node = self._build_block(module.body, entry, exit_node, all_nodes)
        last_node.add_successor(exit_node)

        return ControlFlowGraph("module", entry, exit_node, all_nodes)

    def _is_human_gate_condition(self, test_node: ast.AST) -> bool:
        """Heurística para detectar compuertas de supervisión humana en condiciones."""
        gate_keywords = {
            "human",
            "approved",
            "approval",
            "review",
            "reviewed",
            "authorized",
            "supervisor",
            "manual_check",
            "human_gate",
            "is_approved",
            "verified",
            "accepted",
        }
        for node in ast.walk(test_node):
            if isinstance(node, ast.Name) and any(
                kw in node.id.lower() for kw in gate_keywords
            ):
                return True
            elif isinstance(node, ast.Attribute) and any(
                kw in node.attr.lower() for kw in gate_keywords
            ):
                return True
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if any(
                    kw in node.value.lower()
                    for kw in ["approved", "accepted", "authorized"]
                ):
                    return True
        return False

    def _build_block(
        self,
        stmts: List[ast.stmt],
        current: CFGNode,
        exit_node: CFGNode,
        all_nodes: List[CFGNode],
        loop_targets: Optional[tuple[CFGNode, CFGNode]] = None,
    ) -> CFGNode:
        curr = current

        for stmt in stmts:
            if isinstance(stmt, (ast.If)):
                # Nodo de condición
                cond_node = self._create_node(
                    stmt.test, label=f"IF_COND (Line {stmt.lineno})"
                )
                cond_node.is_branch_condition = True
                cond_node.branch_condition_ast = stmt.test
                cond_node.is_human_gate = self._is_human_gate_condition(stmt.test)
                all_nodes.append(cond_node)
                curr.add_successor(cond_node)

                # Rama THEN (body)
                then_entry = self._create_node(None, label="THEN_BRANCH")
                if cond_node.is_human_gate:
                    then_entry.is_human_gate = True
                all_nodes.append(then_entry)
                cond_node.add_successor(then_entry)
                then_exit = self._build_block(
                    stmt.body, then_entry, exit_node, all_nodes, loop_targets
                )

                # Rama ELSE (orelse)
                else_entry = self._create_node(None, label="ELSE_BRANCH")
                all_nodes.append(else_entry)
                cond_node.add_successor(else_entry)
                if stmt.orelse:
                    else_exit = self._build_block(
                        stmt.orelse, else_entry, exit_node, all_nodes, loop_targets
                    )
                else:
                    else_exit = else_entry

                # Nodo de Unión Phi (convergencia)
                phi_node = self._create_node(
                    None, label=f"PHI_JOIN (Line {stmt.end_lineno})"
                )
                phi_node.is_phi = True
                all_nodes.append(phi_node)

                then_exit.add_successor(phi_node)
                else_exit.add_successor(phi_node)
                curr = phi_node

            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                loop_cond = self._create_node(stmt, label=f"LOOP (Line {stmt.lineno})")
                all_nodes.append(loop_cond)
                curr.add_successor(loop_cond)

                loop_body_entry = self._create_node(None, label="LOOP_BODY")
                all_nodes.append(loop_body_entry)
                loop_cond.add_successor(loop_body_entry)

                loop_exit = self._create_node(None, label="LOOP_EXIT")
                all_nodes.append(loop_exit)
                loop_body_exit = self._build_block(
                    stmt.body,
                    loop_body_entry,
                    exit_node,
                    all_nodes,
                    (loop_cond, loop_exit),
                )
                loop_body_exit.add_successor(loop_cond)  # Back edge

                else_entry = self._create_node(None, label="LOOP_ELSE")
                all_nodes.append(else_entry)
                loop_cond.add_successor(else_entry)
                else_exit = self._build_block(
                    stmt.orelse, else_entry, exit_node, all_nodes, loop_targets
                )
                else_exit.add_successor(loop_exit)
                curr = loop_exit

            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                with_node = self._create_node(stmt, label=f"WITH (Line {stmt.lineno})")
                all_nodes.append(with_node)
                curr.add_successor(with_node)
                curr = self._build_block(
                    stmt.body, with_node, exit_node, all_nodes, loop_targets
                )

            elif isinstance(stmt, (ast.Try, ast.TryStar)):
                try_node = self._create_node(
                    None, label=f"TRY_BLOCK (Line {stmt.lineno})"
                )
                all_nodes.append(try_node)
                curr.add_successor(try_node)
                body_start = len(all_nodes)
                body_exit = self._build_block(
                    stmt.body, try_node, exit_node, all_nodes, loop_targets
                )
                body_nodes = [try_node, *all_nodes[body_start:]]
                normal_exit = self._build_block(
                    stmt.orelse, body_exit, exit_node, all_nodes, loop_targets
                )
                join = self._create_node(None, label="TRY_JOIN")
                join.is_phi = True
                all_nodes.append(join)
                normal_exit.add_successor(join)

                for handler in stmt.handlers:
                    except_node = self._create_node(None, label="EXCEPT_HANDLER")
                    all_nodes.append(except_node)
                    for body_node in body_nodes:
                        body_node.add_successor(except_node)
                    handler_exit = self._build_block(
                        handler.body, except_node, exit_node, all_nodes, loop_targets
                    )
                    handler_exit.add_successor(join)
                if stmt.finalbody:
                    protected_nodes = [try_node, *all_nodes[body_start:]]
                    protected_set = set(protected_nodes)
                    abrupt_exits: dict[CFGNode, list[CFGNode]] = {}
                    for protected_node in protected_nodes:
                        for destination in list(protected_node.successors):
                            if destination not in protected_set:
                                abrupt_exits.setdefault(destination, []).append(
                                    protected_node
                                )
                                protected_node.successors.remove(destination)
                                destination.predecessors.remove(protected_node)

                    for destination, predecessors in abrupt_exits.items():
                        abrupt_finally = self._create_node(
                            None, label="FINALLY_ABRUPT"
                        )
                        all_nodes.append(abrupt_finally)
                        for predecessor in predecessors:
                            predecessor.add_successor(abrupt_finally)
                        finally_exit = self._build_block(
                            stmt.finalbody,
                            abrupt_finally,
                            exit_node,
                            all_nodes,
                            loop_targets,
                        )
                        finally_exit.add_successor(destination)

                    finally_entry = self._create_node(None, label="FINALLY")
                    all_nodes.append(finally_entry)
                    join.add_successor(finally_entry)
                    curr = self._build_block(
                        stmt.finalbody,
                        finally_entry,
                        exit_node,
                        all_nodes,
                        loop_targets,
                    )
                else:
                    curr = join

            elif isinstance(
                stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue

            else:
                stmt_node = self._create_node(
                    stmt, label=f"STMT {stmt.__class__.__name__} (Line {stmt.lineno})"
                )
                all_nodes.append(stmt_node)
                curr.add_successor(stmt_node)
                curr = stmt_node
                if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                    if isinstance(stmt, (ast.Break, ast.Continue)) and loop_targets:
                        curr.add_successor(
                            loop_targets[0 if isinstance(stmt, ast.Continue) else 1]
                        )
                    else:
                        curr.add_successor(exit_node)
                    curr = self._create_node(None, label="UNREACHABLE")
                    all_nodes.append(curr)

        return curr
