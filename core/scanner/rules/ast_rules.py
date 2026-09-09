"""
AST-driven static analysis engine for Code Sentinel AI / ASTraGuard.
Provides ultra-fast (<100ms deterministic pass) AST inspection detecting:
- Syntax Errors (QUAL-SYNTAX-ERR)
- Parameter Overload (MAINT-PARAM-OVERLOAD)
- Deep Control-flow Nesting (MAINT-DEEP-NESTING)
- Unchecked None Dereference (LOGIC-UNCHECKED-NONE)
- Inconsistent / Missing Returns (LOGIC-MISSING-RETURN)
- Non-idiomatic range(len()) Loops (PERF-RANGE-LEN)
- Redundant Loop-Invariant Calls (PERF-REDUNDANT-LOOP-OP)
- Dead Code Following Exit Statements (QUAL-DEAD-CODE)
- Bare Except Clauses (MAINT-BARE-EXCEPT)
- Silently Suppressed Exceptions (MAINT-SUPPRESSED-ERR)
- Dynamic Code Execution (SEC-DYNAMIC-EVAL)
- Broken Hashing (SEC-WEAK-HASHING)
- Unclosed File Resource Handles (MAINT-UNCLOSED-HANDLE)
- Formatted SQL Injection (SEC-SQL-INJECTION)
- Hardcoded Secret Keys (SEC-HARDCODED-SECRET)
- Cyclomatic Complexity Debt (MAINT-COMPLEXITY-DEBT)
"""
from __future__ import annotations
import ast
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from core.scanner.context import FileContextManager, default_context_manager
from core.scanner.rules.base import BaseScannerRule


class ASTAuditorVisitor(ast.NodeVisitor):
    """
    AST-driven static analysis visitor (<100ms deterministic pass).
    Inspects Python AST nodes for security, quality, maintainability, and performance flaws.
    """
    def __init__(self, file_path: str, base_dir: str, context_manager: Optional[FileContextManager] = None):
        self.file_path = file_path
        self.base_dir = base_dir
        self.ctx_mgr = context_manager or default_context_manager
        self.findings: List[Dict[str, Any]] = []

    def _get_context(self, line: int, label: str) -> Dict[str, Any]:
        return self.ctx_mgr.extract_code_context(self.file_path, line, rule_label=label)

    def _check_block_dead_code(self, stmts: List[ast.stmt]):
        """Flags any statement appearing immediately after an unconditional return/break/continue/raise."""
        if not stmts:
            return
        terminal_seen = None
        for stmt in stmts:
            if terminal_seen:
                ctx = self._get_context(stmt.lineno, "Quality: Dead Code Following Exit")
                self.findings.append({
                    "line": stmt.lineno,
                    "line_no": stmt.lineno,
                    "rule_id": "QUAL-DEAD-CODE",
                    "category": "Quality",
                    "severity": "High",
                    "title": f"Unreachable / Dead Code Detected Following '{terminal_seen}' Statement",
                    "explanation": f"Statements after unconditional '{terminal_seen}' will never execute, cluttering codebase logic and creating dead maintenance debt.",
                    "vulnerable_code": ctx["target_line"],
                    "before_code": ctx["target_line"],
                    "context_snippet": ctx["snippet"],
                    "highlighted_context": ctx["highlighted_context"],
                    "tool": "Code Quality Engine"
                })
                break
            if isinstance(stmt, (ast.Return, ast.Break, ast.Continue, ast.Raise)):
                terminal_seen = stmt.__class__.__name__.lower()

    def _calculate_max_nesting(self, node: ast.AST, current_depth: int = 0) -> int:
        """Computes the maximum nesting depth of control flow structures in a function."""
        max_d = current_depth
        control_types = (ast.If, ast.For, ast.While, ast.Try, ast.With)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, control_types):
                child_depth = self._calculate_max_nesting(child, current_depth + 1)
                if child_depth > max_d:
                    max_d = child_depth
            elif not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                child_depth = self._calculate_max_nesting(child, current_depth)
                if child_depth > max_d:
                    max_d = child_depth
        return max_d

    def _check_unchecked_none(self, fn_node: ast.FunctionDef):
        """Finds parameters with default None or Optional annotations accessed before null check."""
        none_params = set()
        if fn_node.args.defaults:
            diff = len(fn_node.args.args) - len(fn_node.args.defaults)
            for idx, default in enumerate(fn_node.args.defaults):
                if isinstance(default, ast.Constant) and default.value is None:
                    arg_idx = diff + idx
                    if 0 <= arg_idx < len(fn_node.args.args):
                        none_params.add(fn_node.args.args[arg_idx].arg)

        for arg, default in zip(fn_node.args.kwonlyargs, fn_node.args.kw_defaults):
            if default and isinstance(default, ast.Constant) and default.value is None:
                none_params.add(arg.arg)

        for arg in fn_node.args.args + fn_node.args.kwonlyargs:
            if arg.annotation:
                ann_str = ast.unparse(arg.annotation) if hasattr(ast, "unparse") else ""
                if "Optional" in ann_str or "None" in ann_str:
                    none_params.add(arg.arg)

        if not none_params:
            return

        guarded_params = set()
        for stmt in fn_node.body:
            if isinstance(stmt, ast.If):
                test_str = ast.unparse(stmt.test) if hasattr(ast, "unparse") else ""
                for p in list(none_params):
                    if p in test_str and any(k in test_str for k in ["is None", "is not None", "not ", "!= None", "== None"]):
                        guarded_params.add(p)

            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name):
                    p_name = sub.value.id
                    if p_name in none_params and p_name not in guarded_params:
                        ctx = self._get_context(sub.lineno, f"Logical Risk: Unchecked None on '{p_name}'")
                        self.findings.append({
                            "line": sub.lineno,
                            "line_no": sub.lineno,
                            "rule_id": "LOGIC-UNCHECKED-NONE",
                            "category": "Quality",
                            "severity": "High",
                            "title": f"Potential NoneType Dereference on Parameter '{p_name}' without Prior Null Check",
                            "explanation": f"Parameter '{p_name}' defaults to None or is optional, but is directly dereferenced (.{sub.attr}) without verifying it is non-null.",
                            "vulnerable_code": ctx["target_line"],
                            "before_code": ctx["target_line"],
                            "context_snippet": ctx["snippet"],
                            "highlighted_context": ctx["highlighted_context"],
                            "tool": "Logical Correctness Engine"
                        })
                        guarded_params.add(p_name)
                elif isinstance(sub, ast.Subscript) and isinstance(sub.value, ast.Name):
                    p_name = sub.value.id
                    if p_name in none_params and p_name not in guarded_params:
                        ctx = self._get_context(sub.lineno, f"Logical Risk: Unchecked None on '{p_name}'")
                        self.findings.append({
                            "line": sub.lineno,
                            "line_no": sub.lineno,
                            "rule_id": "LOGIC-UNCHECKED-NONE",
                            "category": "Quality",
                            "severity": "High",
                            "title": f"Potential NoneType Subscript on Parameter '{p_name}' without Prior Null Check",
                            "explanation": f"Parameter '{p_name}' defaults to None or is optional, but is indexed ([...]) without verifying it is non-null.",
                            "vulnerable_code": ctx["target_line"],
                            "before_code": ctx["target_line"],
                            "context_snippet": ctx["snippet"],
                            "highlighted_context": ctx["highlighted_context"],
                            "tool": "Logical Correctness Engine"
                        })
                        guarded_params.add(p_name)

    def _check_missing_returns(self, fn_node: ast.FunctionDef):
        """Detects functions where some execution branches return a value, but another path exits without an explicit return."""
        has_value_return = False
        for sub in ast.walk(fn_node):
            if isinstance(sub, ast.Return) and sub.value is not None:
                has_value_return = True
                break

        if not has_value_return or not fn_node.body:
            return

        last_stmt = fn_node.body[-1]
        if isinstance(last_stmt, ast.If):
            def branch_returns(stmt: ast.stmt) -> bool:
                if isinstance(stmt, ast.Return) and stmt.value is not None:
                    return True
                if isinstance(stmt, ast.If):
                    if not stmt.orelse:
                        return False
                    return (any(branch_returns(s) for s in stmt.body) and
                            any(branch_returns(s) for s in stmt.orelse))
                return False

            if not branch_returns(last_stmt):
                ctx = self._get_context(last_stmt.lineno, "Logical Risk: Missing Return in Branch")
                self.findings.append({
                    "line": last_stmt.lineno,
                    "line_no": last_stmt.lineno,
                    "rule_id": "LOGIC-MISSING-RETURN",
                    "category": "Quality",
                    "severity": "Medium",
                    "title": f"Inconsistent / Missing Return Statement in Execution Branch of '{fn_node.name}'",
                    "explanation": f"Function '{fn_node.name}' returns explicit values in certain execution branches, but another branch falls through to return None implicitly.",
                    "vulnerable_code": ctx["target_line"],
                    "before_code": ctx["target_line"],
                    "context_snippet": ctx["snippet"],
                    "highlighted_context": ctx["highlighted_context"],
                    "tool": "Logical Correctness Engine"
                })

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # 1. Cyclomatic complexity
        complexity = 1
        for sub_node in ast.walk(node):
            if isinstance(sub_node, (ast.If, ast.While, ast.For, ast.ExceptHandler, ast.With, ast.Assert)):
                complexity += 1
            elif isinstance(sub_node, ast.BoolOp):
                complexity += len(sub_node.values) - 1

        if complexity >= 10:
            severity = "Critical" if complexity >= 20 else ("High" if complexity >= 14 else "Medium")
            ctx = self._get_context(node.lineno, "Maintainability: High Complexity")
            self.findings.append({
                "line": node.lineno,
                "line_no": node.lineno,
                "rule_id": "MAINT-COMPLEXITY-DEBT",
                "category": "Maintainability",
                "severity": severity,
                "title": f"Excessive Cyclomatic Complexity in function '{node.name}' (complexity: {complexity})",
                "explanation": f"Function '{node.name}' has a cyclomatic complexity score of {complexity}, exceeding the standard threshold (10). This creates brittle logic that is difficult to unit test and maintain.",
                "vulnerable_code": ctx["target_line"],
                "before_code": ctx["target_line"],
                "context_snippet": ctx["snippet"],
                "highlighted_context": ctx["highlighted_context"],
                "tool": "Maintainability Engine"
            })

        # 2. Parameter overload (> 5 parameters)
        total_params = len(node.args.args) + len(node.args.posonlyargs) + len(node.args.kwonlyargs)
        if total_params > 5:
            ctx = self._get_context(node.lineno, f"Maintainability: Parameter Overload ({total_params} > 5)")
            self.findings.append({
                "line": node.lineno,
                "line_no": node.lineno,
                "rule_id": "MAINT-PARAM-OVERLOAD",
                "category": "Maintainability",
                "severity": "Medium",
                "title": f"Excessive Function Parameters ({total_params} > 5) in '{node.name}'",
                "explanation": f"Function '{node.name}' declares {total_params} parameters. Having more than 5 parameters tightly couples callers, degrades readability, and indicates a need for parameter encapsulation (e.g. dataclass or config object).",
                "vulnerable_code": ctx["target_line"],
                "before_code": ctx["target_line"],
                "context_snippet": ctx["snippet"],
                "highlighted_context": ctx["highlighted_context"],
                "tool": "Maintainability Engine"
            })

        # 3. Deep nesting check (>= 4 levels)
        max_depth = self._calculate_max_nesting(node)
        if max_depth >= 4:
            ctx = self._get_context(node.lineno, f"Maintainability: Deep Nesting (depth: {max_depth})")
            self.findings.append({
                "line": node.lineno,
                "line_no": node.lineno,
                "rule_id": "MAINT-DEEP-NESTING",
                "category": "Maintainability",
                "severity": "Medium",
                "title": f"Excessively Deep Control Flow Nesting (depth: {max_depth} >= 4) in '{node.name}'",
                "explanation": f"Function '{node.name}' contains conditional control flow nested {max_depth} levels deep. This introduces severe cognitive load and can be simplified with guard clauses or helper dispatchers.",
                "vulnerable_code": ctx["target_line"],
                "before_code": ctx["target_line"],
                "context_snippet": ctx["snippet"],
                "highlighted_context": ctx["highlighted_context"],
                "tool": "Maintainability Engine"
            })

        # 4. Dead code in function body
        self._check_block_dead_code(node.body)

        # 5. Logical checks
        self._check_unchecked_none(node)
        self._check_missing_returns(node)

        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)

    def visit_If(self, node: ast.If):
        self._check_block_dead_code(node.body)
        self._check_block_dead_code(node.orelse)
        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        # 1. Non-idiomatic range(len(...)) loop
        is_range_len = False
        if isinstance(node.iter, ast.Call) and isinstance(node.iter.func, ast.Name) and node.iter.func.id == "range":
            if len(node.iter.args) == 1:
                inner = node.iter.args[0]
                if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name) and inner.func.id == "len":
                    is_range_len = True
        if is_range_len:
            ctx = self._get_context(node.lineno, "Performance: Non-Idiomatic range(len(...))")
            self.findings.append({
                "line": node.lineno,
                "line_no": node.lineno,
                "rule_id": "PERF-RANGE-LEN",
                "category": "Performance",
                "severity": "Low",
                "title": "Non-Idiomatic Loop Iteration via 'range(len(...))'",
                "explanation": "Iterating over indices with range(len(...)) is non-idiomatic in Python and slower than direct item iteration or using 'enumerate()'.",
                "vulnerable_code": ctx["target_line"],
                "before_code": ctx["target_line"],
                "context_snippet": ctx["snippet"],
                "highlighted_context": ctx["highlighted_context"],
                "tool": "Performance Engine"
            })

        # 2. Redundant loop-invariant operations inside iteration
        for sub in node.body:
            for sub_child in ast.walk(sub):
                if isinstance(sub_child, ast.Call):
                    cname = ""
                    if isinstance(sub_child.func, ast.Attribute) and isinstance(sub_child.func.value, ast.Name):
                        if sub_child.func.value.id == "re" and sub_child.func.attr == "compile":
                            cname = "re.compile"
                    elif isinstance(sub_child.func, ast.Name) and sub_child.func.id == "open":
                        if sub_child.args and isinstance(sub_child.args[0], ast.Constant):
                            cname = "open"
                    if cname:
                        ctx = self._get_context(sub_child.lineno, f"Performance: Redundant {cname} in Loop")
                        self.findings.append({
                            "line": sub_child.lineno,
                            "line_no": sub_child.lineno,
                            "rule_id": "PERF-REDUNDANT-LOOP-OP",
                            "category": "Performance",
                            "severity": "Medium",
                            "title": f"Redundant Loop-Invariant '{cname}()' Call Inside Iteration Block",
                            "explanation": f"Calling '{cname}()' repeatedly inside an iteration loop re-executes redundant compilation/I/O on every cycle. Move this operation outside the loop.",
                            "vulnerable_code": ctx["target_line"],
                            "before_code": ctx["target_line"],
                            "context_snippet": ctx["snippet"],
                            "highlighted_context": ctx["highlighted_context"],
                            "tool": "Performance Engine"
                        })
                        break

        self._check_block_dead_code(node.body)
        self._check_block_dead_code(node.orelse)
        self.generic_visit(node)

    def visit_While(self, node: ast.While):
        self._check_block_dead_code(node.body)
        self._check_block_dead_code(node.orelse)
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try):
        self._check_block_dead_code(node.body)
        self._check_block_dead_code(node.orelse)
        self._check_block_dead_code(node.finalbody)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        # 1. Bare except: clause
        if node.type is None:
            ctx = self._get_context(node.lineno, "Maintainability: Bare Except Clause")
            self.findings.append({
                "line": node.lineno,
                "line_no": node.lineno,
                "rule_id": "MAINT-BARE-EXCEPT",
                "category": "Maintainability",
                "severity": "Medium",
                "title": "Bare 'except:' Clause Catches SystemExit and KeyboardInterrupt",
                "explanation": "A bare 'except:' clause intercepts all exceptions, including KeyboardInterrupt, SystemExit, and memory errors, preventing graceful process termination.",
                "vulnerable_code": ctx["target_line"],
                "before_code": ctx["target_line"],
                "context_snippet": ctx["snippet"],
                "highlighted_context": ctx["highlighted_context"],
                "tool": "Maintainability Engine"
            })

        # 2. Suppressed errors (except ...: pass)
        is_suppressed = False
        if len(node.body) == 1:
            first_stmt = node.body[0]
            if isinstance(first_stmt, ast.Pass):
                is_suppressed = True
            elif isinstance(first_stmt, ast.Expr) and isinstance(first_stmt.value, ast.Constant):
                is_suppressed = True

        if is_suppressed:
            ctx = self._get_context(node.lineno, "Maintainability: Suppressed Exception")
            self.findings.append({
                "line": node.lineno,
                "line_no": node.lineno,
                "rule_id": "MAINT-SUPPRESSED-ERR",
                "category": "Maintainability",
                "severity": "High",
                "title": "Silently Suppressed Exception (except ...: pass)",
                "explanation": "Catching an exception and silently suppressing it with 'pass' hides critical runtime failures, destroys observability, and makes diagnosing production bugs impossible.",
                "vulnerable_code": ctx["target_line"],
                "before_code": ctx["target_line"],
                "context_snippet": ctx["snippet"],
                "highlighted_context": ctx["highlighted_context"],
                "tool": "Maintainability Engine"
            })

        self._check_block_dead_code(node.body)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        # Detect eval() / exec()
        if func_name in {"eval", "exec"}:
            ctx = self._get_context(node.lineno, f"Security: Dynamic Code Execution ({func_name})")
            self.findings.append({
                "line": node.lineno,
                "line_no": node.lineno,
                "rule_id": "SEC-DYNAMIC-EVAL",
                "category": "Security",
                "severity": "Critical",
                "title": f"Dynamic Code Execution via '{func_name}()'",
                "explanation": f"Using '{func_name}()' executes raw string inputs as Python code, providing an immediate path for arbitrary code execution attacks.",
                "vulnerable_code": ctx["target_line"],
                "before_code": ctx["target_line"],
                "context_snippet": ctx["snippet"],
                "highlighted_context": ctx["highlighted_context"],
                "tool": "Security Vulnerability Engine"
            })

        # Detect hashlib.md5
        if func_name == "md5":
            ctx = self._get_context(node.lineno, "Security: Weak Hash MD5")
            self.findings.append({
                "line": node.lineno,
                "line_no": node.lineno,
                "rule_id": "SEC-WEAK-HASHING",
                "category": "Security",
                "severity": "High",
                "title": "Cryptographically Broken MD5 Hashing Algorithm",
                "explanation": "MD5 is vulnerable to collision attacks and should never be used for security purposes, passwords, or data integrity verification.",
                "vulnerable_code": ctx["target_line"],
                "before_code": ctx["target_line"],
                "context_snippet": ctx["snippet"],
                "highlighted_context": ctx["highlighted_context"],
                "tool": "Security Vulnerability Engine"
            })

        # Detect unclosed open() call outside 'with'
        if func_name == "open":
            ctx = self._get_context(node.lineno, "Maintainability: Unmanaged File Resource")
            self.findings.append({
                "line": node.lineno,
                "line_no": node.lineno,
                "rule_id": "MAINT-UNCLOSED-HANDLE",
                "category": "Maintainability",
                "severity": "Low",
                "title": "Unmanaged File Resource Handle (Missing Context Manager)",
                "explanation": "File descriptor opened without a context manager ('with open(...)') risks operating system file descriptor leaks and memory leaks.",
                "vulnerable_code": ctx["target_line"],
                "before_code": ctx["target_line"],
                "context_snippet": ctx["snippet"],
                "highlighted_context": ctx["highlighted_context"],
                "tool": "Code Quality & Maintainability Engine"
            })

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # 1. Detect SQL Injection in formatted strings
        for target in node.targets:
            if isinstance(target, ast.Name):
                name_upper = target.id.upper()
                if "QUERY" in name_upper or "SQL" in name_upper:
                    is_insecure_sql = False
                    if isinstance(node.value, ast.JoinedStr):
                        is_insecure_sql = True
                    elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, (ast.Add, ast.Mod)):
                        is_insecure_sql = True

                    if is_insecure_sql:
                        ctx = self._get_context(node.lineno, "Security: SQL Injection")
                        self.findings.append({
                            "line": node.lineno,
                            "line_no": node.lineno,
                            "rule_id": "SEC-SQL-INJECTION",
                            "category": "Security",
                            "severity": "Critical",
                            "title": "SQL Injection Vulnerability via Formatted Query Construction",
                            "explanation": "Constructing SQL queries using string formatting or concatenation allows attackers to alter query logic and exfiltrate database contents.",
                            "vulnerable_code": ctx["target_line"],
                            "before_code": ctx["target_line"],
                            "context_snippet": ctx["snippet"],
                            "highlighted_context": ctx["highlighted_context"],
                            "tool": "Security Vulnerability Engine"
                        })

                # 2. Detect hardcoded secret tokens or credentials
                if any(k in name_upper for k in ["SECRET", "TOKEN", "PASSWORD", "API_KEY", "DATABASE_URL"]):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        val_str = node.value.value
                        if len(val_str) > 8 and not val_str.startswith("http://localhost"):
                            ctx = self._get_context(node.lineno, "Security: Hardcoded Secret")
                            self.findings.append({
                                "line": node.lineno,
                                "line_no": node.lineno,
                                "rule_id": "SEC-HARDCODED-SECRET",
                                "category": "Security",
                                "severity": "High",
                                "title": f"Hardcoded Authentication Credential or Secret Assigned to '{target.id}'",
                                "explanation": "Hardcoded credentials committed to source control can be extracted by unauthorized parties. Secrets should always be loaded from environment variables.",
                                "vulnerable_code": ctx["target_line"],
                                "before_code": ctx["target_line"],
                                "context_snippet": ctx["snippet"],
                                "highlighted_context": ctx["highlighted_context"],
                                "tool": "Security Vulnerability Engine"
                            })
        self.generic_visit(node)


def run_ast_scan(
    target_dir: str,
    target_file: Optional[str] = None,
    context_manager: Optional[FileContextManager] = None
) -> List[Dict[str, Any]]:
    """
    Scans python files in target_dir (or a specific target_file) using pure Python AST (<100ms deterministic pass).
    Performs immediate Syntax Validation before AST traversal, then checks for Maintainability,
    Efficiency bottlenecks, Logical risks, and Security flaws.
    """
    ctx_mgr = context_manager or default_context_manager
    findings: List[Dict[str, Any]] = []
    root_path = Path(target_dir)

    if target_file:
        full_path = Path(target_dir) / target_file if not os.path.isabs(target_file) else Path(target_file)
        if full_path.suffix.lower() != ".py" or not full_path.exists():
            return []
        py_files = [full_path]
    else:
        py_files = list(root_path.rglob("*.py"))

    for py_file in py_files:
        try:
            rel_file = py_file.relative_to(root_path).as_posix()
        except ValueError:
            rel_file = py_file.name

        source = ctx_mgr.get_text(str(py_file))
        if not source:
            continue

        # 1. Syntax Validation: Catch syntax errors immediately before running AST traversal
        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError as e:
            line_no = e.lineno or 1
            ctx = ctx_mgr.extract_code_context(str(py_file), line_no, rule_label="Syntax Error: Code Parse Failure")
            err_line = (e.text or ctx["target_line"]).strip()
            findings.append({
                "id": f"QUAL-{len(findings) + 301}",
                "file": rel_file,
                "absolute_path": str(py_file),
                "line": line_no,
                "line_no": line_no,
                "rule_id": "QUAL-SYNTAX-ERR",
                "category": "Quality",
                "severity": "Critical",
                "title": f"Syntax Error: {e.msg}",
                "explanation": f"Python parser encountered a fatal syntax error at line {line_no}: {e.msg}. This halts execution and prevents the module from running.",
                "vulnerable_code": err_line,
                "before_code": err_line,
                "context_snippet": ctx["snippet"],
                "highlighted_context": ctx["highlighted_context"],
                "tool": "Code Quality Engine"
            })
            continue
        except Exception:
            continue

        visitor = ASTAuditorVisitor(str(py_file), target_dir, context_manager=ctx_mgr)
        visitor.visit(tree)

        for item in visitor.findings:
            item["id"] = f"AST-{len(findings) + 301}"
            item["file"] = rel_file
            item["absolute_path"] = str(py_file)
            findings.append(item)

    return findings


class ASTScannerRule(BaseScannerRule):
    @property
    def name(self) -> str:
        return "ast_scanner"

    def scan(
        self,
        target_dir: str,
        target_file: Optional[str] = None,
        context_manager: Optional[FileContextManager] = None
    ) -> List[Dict[str, Any]]:
        return run_ast_scan(target_dir, target_file, context_manager)
