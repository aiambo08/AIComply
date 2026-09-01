"""
AIComply - Intra-Procedural Control Flow Graph (CFG) Builder
Construye grafos de flujo de control para funciones y bloques de código,
identificando bifurcaciones y puntos de unión phi para análisis de taint.
"""

import ast
from typing import Dict, List, Optional, Set


class CFGNode:
    """Nodo en el Grafo de Control de Flujo."""

    def __init__(self, node_id: int, ast_node: Optional[ast.AST], label: str = "") -> None:
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

    def __init__(self, name: str, entry: CFGNode, exit_node: CFGNode, nodes: List[CFGNode]) -> None:
        self.name = name
        self.entry = entry
        self.exit_node = exit_node
        self.nodes = nodes

    def get_topological_order(self) -> List[CFGNode]:
        """Retorna los nodos en orden aproximado de ejecución topológica."""
        visited: Set[int] = set()
        order: List[CFGNode] = []

        def dfs(curr: CFGNode) -> None:
            if curr.node_id in visited:
                return
            visited.add(curr.node_id)
            for succ in curr.successors:
                dfs(succ)
            order.append(curr)

        dfs(self.entry)
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

    def build_for_function(self, func_def: ast.FunctionDef | ast.AsyncFunctionDef) -> ControlFlowGraph:
        """Construye el CFG para una definición de función."""
        entry = self._create_node(func_def, label=f"ENTRY: {func_def.name}")
        exit_node = self._create_node(None, label=f"EXIT: {func_def.name}")
        all_nodes = [entry, exit_node]

        last_node = self._build_block(func_def.body, entry, exit_node, all_nodes)
        last_node.add_successor(exit_node)

        return ControlFlowGraph(func_def.name, entry, exit_node, all_nodes)

    def build_for_module(self, module: ast.Module) -> ControlFlowGraph:
        """Construye el CFG para el nivel de módulo principal."""
        entry = self._create_node(module, label="ENTRY: module")
        exit_node = self._create_node(None, label="EXIT: module")
        all_nodes = [entry, exit_node]

        last_node = self._build_block(module.body, entry, exit_node, all_nodes)
        last_node.add_successor(exit_node)

        return ControlFlowGraph("module", entry, exit_node, all_nodes)

    def _is_human_gate_condition(self, test_node: ast.AST) -> bool:
        """Heurística para detectar compuertas de supervisión humana en condiciones."""
        gate_keywords = {
            "human", "approved", "approval", "review", "reviewed", 
            "authorized", "supervisor", "manual_check", "human_gate",
            "is_approved", "verified", "accepted"
        }
        for node in ast.walk(test_node):
            if isinstance(node, ast.Name) and any(kw in node.id.lower() for kw in gate_keywords):
                return True
            elif isinstance(node, ast.Attribute) and any(kw in node.attr.lower() for kw in gate_keywords):
                return True
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if any(kw in node.value.lower() for kw in ["approved", "accepted", "authorized"]):
                    return True
        return False

    def _build_block(
        self,
        stmts: List[ast.stmt],
        current: CFGNode,
        exit_node: CFGNode,
        all_nodes: List[CFGNode],
    ) -> CFGNode:
        curr = current

        for stmt in stmts:
            if isinstance(stmt, (ast.If)):
                # Nodo de condición
                cond_node = self._create_node(stmt.test, label=f"IF_COND (Line {stmt.lineno})")
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
                then_exit = self._build_block(stmt.body, then_entry, exit_node, all_nodes)

                # Rama ELSE (orelse)
                else_entry = self._create_node(None, label="ELSE_BRANCH")
                all_nodes.append(else_entry)
                cond_node.add_successor(else_entry)
                if stmt.orelse:
                    else_exit = self._build_block(stmt.orelse, else_entry, exit_node, all_nodes)
                else:
                    else_exit = else_entry

                # Nodo de Unión Phi (convergencia)
                phi_node = self._create_node(None, label=f"PHI_JOIN (Line {getattr(stmt, 'end_lineno', stmt.lineno)})")
                phi_node.is_phi = True
                all_nodes.append(phi_node)

                then_exit.add_successor(phi_node)
                else_exit.add_successor(phi_node)
                curr = phi_node

            elif isinstance(stmt, (ast.For, ast.While)):
                loop_cond = self._create_node(stmt, label=f"LOOP (Line {stmt.lineno})")
                all_nodes.append(loop_cond)
                curr.add_successor(loop_cond)

                loop_body_entry = self._create_node(None, label="LOOP_BODY")
                all_nodes.append(loop_body_entry)
                loop_cond.add_successor(loop_body_entry)

                loop_body_exit = self._build_block(stmt.body, loop_body_entry, exit_node, all_nodes)
                loop_body_exit.add_successor(loop_cond)  # Back edge

                loop_exit = self._create_node(None, label="LOOP_EXIT")
                all_nodes.append(loop_exit)
                loop_cond.add_successor(loop_exit)
                curr = loop_exit

            elif isinstance(stmt, (ast.Try)):
                try_node = self._create_node(stmt, label=f"TRY_BLOCK (Line {stmt.lineno})")
                all_nodes.append(try_node)
                curr.add_successor(try_node)
                curr = self._build_block(stmt.body, try_node, exit_node, all_nodes)

                for handler in stmt.handlers:
                    except_node = self._create_node(handler, label="EXCEPT_HANDLER")
                    all_nodes.append(except_node)
                    try_node.add_successor(except_node)
                    handler_exit = self._build_block(handler.body, except_node, exit_node, all_nodes)
                    handler_exit.add_successor(curr)

            else:
                stmt_node = self._create_node(stmt, label=f"STMT {stmt.__class__.__name__} (Line {getattr(stmt, 'lineno', 0)})")
                all_nodes.append(stmt_node)
                curr.add_successor(stmt_node)
                curr = stmt_node

        return curr
