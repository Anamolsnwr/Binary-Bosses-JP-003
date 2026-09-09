"""
Static Analysis Engine for Code Sentinel AI.
Combines Bandit (security vulnerabilities), Radon (cyclomatic complexity & maintainability),
and an AST-based heuristic engine with unified standardization.
"""
import ast
import json
import os
import re
import sys
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional


SEVERITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low"
}


def _extract_code_context(file_path: str, line_number: int, context_lines: int = 8, rule_label: str = "Issue Detected") -> Dict[str, Any]:
    """Extracts the flagged line, surrounding code with line highlight, and snippet using proper language comment syntax."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        
        total_lines = len(lines)
        if line_number < 1 or line_number > total_lines:
            return {"target_line": "", "snippet": "", "highlighted_context": "", "start_line": 1, "end_line": 1}

        target_line = lines[line_number - 1].rstrip("\r\n")
        start_idx = max(0, line_number - 1 - context_lines)
        end_idx = min(total_lines, line_number + context_lines)

        # Choose comment syntax based on file extension
        ext = os.path.splitext(file_path)[1].lower()
        if ext in {".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".cpp", ".cs", ".go", ".php"}:
            cmt_open, cmt_close = "//", ""
        elif ext in {".html", ".xml"}:
            cmt_open, cmt_close = "<!--", " -->"
        elif ext in {".css"}:
            cmt_open, cmt_close = "/*", " */"
        else:
            cmt_open, cmt_close = "#", ""

        # Clean tool names out of label
        clean_label = rule_label
        for tool_name in ["bandit:", "radon:", "ast:", "tool:"]:
            if tool_name in clean_label.lower():
                clean_label = clean_label.split(":")[-1].replace("_", " ").title()

        snippet_lines = []
        highlighted_lines = []
        for idx in range(start_idx, end_idx):
            ln = idx + 1
            raw = lines[idx].rstrip("\r\n")
            if ln == line_number:
                snippet_lines.append(f">> {ln:4d} | {raw}")
                indent = " " * (len(raw) - len(raw.lstrip()))
                banner = f"{cmt_open} 🚨 [ISSUE DETECTED AT LINE {ln} - {clean_label.upper()}]{cmt_close}".strip()
                callout = f"{cmt_open} <-- ERROR DETECTED HERE{cmt_close}".strip()
                highlighted_lines.append(f"{indent}{banner}")
                highlighted_lines.append(f"{raw}  {callout}")
            else:
                snippet_lines.append(f"   {ln:4d} | {raw}")
                highlighted_lines.append(raw)

        return {
            "target_line": target_line.strip(),
            "snippet": "\n".join(snippet_lines),
            "highlighted_context": "\n".join(highlighted_lines),
            "start_line": start_idx + 1,
            "end_line": end_idx
        }
    except Exception:
        return {"target_line": "", "snippet": "", "highlighted_context": "", "start_line": line_number, "end_line": line_number}


def run_bandit_scan(target_dir: str, target_file: Optional[str] = None) -> List[Dict[str, Any]]:
    """Runs Bandit security linter via CLI subprocess and returns standardized findings."""
    findings = []
    try:
        # Use current Python interpreter to ensure virtualenv packages are discovered
        if target_file:
            full_path = os.path.normpath(os.path.join(target_dir, target_file) if not os.path.isabs(target_file) else target_file)
            if not full_path.endswith(".py") or not os.path.exists(full_path):
                return []
            cmd = [sys.executable, "-m", "bandit", full_path, "-f", "json", "-q"]
        else:
            cmd = [sys.executable, "-m", "bandit", "-r", target_dir, "-f", "json", "-q"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                for item in data.get("results", []):
                    rel_file = os.path.relpath(item.get("filename", ""), target_dir).replace("\\", "/")
                    if target_file and rel_file != Path(target_file).as_posix() and item.get("filename", "") != target_file:
                        continue
                    severity = item.get("issue_severity", "MEDIUM").capitalize()
                    
                    # Upgrade direct injection or exec to Critical
                    test_id = item.get("test_id", "")
                    if test_id in {"B608", "B102", "B307"}:
                        severity = "Critical"
                    elif severity not in {"Critical", "High", "Medium", "Low"}:
                        severity = "Medium"

                    test_name = item.get("test_name", "security_issue")
                    ctx = _extract_code_context(item.get("filename", ""), item.get("line_number", 1), rule_label=f"bandit:{test_id}:{test_name}")
                    
                    findings.append({
                        "id": f"SEC-{len(findings) + 101}",
                        "file": rel_file,
                        "absolute_path": item.get("filename", ""),
                        "line": item.get("line_number", 1),
                        "rule_id": f"bandit:{test_id}:{test_name}",
                        "category": "Security",
                        "severity": severity,
                        "title": item.get("issue_text", "Security vulnerability detected"),
                        "vulnerable_code": ctx["target_line"] or item.get("code", "").strip(),
                        "context_snippet": ctx["snippet"],
                        "highlighted_context": ctx["highlighted_context"],
                        "tool": "bandit"
                    })
            except json.JSONDecodeError:
                pass
    except Exception:
        pass

    return findings


def run_radon_complexity_scan(target_dir: str, target_file: Optional[str] = None) -> List[Dict[str, Any]]:
    """Runs Radon cyclomatic complexity analysis and returns standardized findings."""
    findings = []
    try:
        if target_file:
            full_path = os.path.normpath(os.path.join(target_dir, target_file) if not os.path.isabs(target_file) else target_file)
            if not full_path.endswith(".py") or not os.path.exists(full_path):
                return []
            cmd = [sys.executable, "-m", "radon", "cc", full_path, "-j"]
        else:
            cmd = [sys.executable, "-m", "radon", "cc", target_dir, "-j"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                for file_path, items in data.items():
                    rel_file = os.path.relpath(file_path, target_dir).replace("\\", "/")
                    if target_file and rel_file != Path(target_file).as_posix() and file_path != target_file:
                        continue
                    for func in items:
                        complexity = func.get("complexity", 1)
                        if complexity >= 10:
                            if complexity >= 25:
                                severity = "Critical"
                            elif complexity >= 15:
                                severity = "High"
                            else:
                                severity = "Medium"

                            line_num = func.get("lineno", 1)
                            ctx = _extract_code_context(file_path, line_num, rule_label=f"radon:complexity:{func.get('rank', 'C')}")
                            
                            findings.append({
                                "id": f"MAINT-{len(findings) + 201}",
                                "file": rel_file,
                                "absolute_path": file_path,
                                "line": line_num,
                                "rule_id": f"radon:complexity:{func.get('rank', 'C')}",
                                "category": "Maintainability",
                                "severity": severity,
                                "title": f"High Cyclomatic Complexity in '{func.get('name')}' (score: {complexity})",
                                "vulnerable_code": ctx["target_line"],
                                "context_snippet": ctx["snippet"],
                                "highlighted_context": ctx["highlighted_context"],
                                "tool": "radon"
                            })
            except json.JSONDecodeError:
                pass
    except Exception:
        pass

    return findings


class ASTAuditorVisitor(ast.NodeVisitor):
    """
    Comprehensive AST-driven static analysis engine (<100ms deterministic pass).
    Detects Security Vulnerabilities, Code Quality flaws, Maintainability debt,
    Efficiency bottlenecks, and Logical risks.
    """
    def __init__(self, file_path: str, base_dir: str):
        self.file_path = file_path
        self.base_dir = base_dir
        self.findings = []

    def _check_block_dead_code(self, stmts: List[ast.stmt]):
        """Flags any statement appearing immediately after an unconditional return/break/continue/raise."""
        if not stmts:
            return
        terminal_seen = None
        for stmt in stmts:
            if terminal_seen:
                ctx = _extract_code_context(self.file_path, stmt.lineno, rule_label="Quality: Dead Code Following Exit")
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
                        ctx = _extract_code_context(self.file_path, sub.lineno, rule_label=f"Logical Risk: Unchecked None on '{p_name}'")
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
                        ctx = _extract_code_context(self.file_path, sub.lineno, rule_label=f"Logical Risk: Unchecked None on '{p_name}'")
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
                ctx = _extract_code_context(self.file_path, last_stmt.lineno, rule_label="Logical Risk: Missing Return in Branch")
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
            ctx = _extract_code_context(self.file_path, node.lineno, rule_label="Maintainability: High Complexity")
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
            ctx = _extract_code_context(self.file_path, node.lineno, rule_label=f"Maintainability: Parameter Overload ({total_params} > 5)")
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
            ctx = _extract_code_context(self.file_path, node.lineno, rule_label=f"Maintainability: Deep Nesting (depth: {max_depth})")
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
            ctx = _extract_code_context(self.file_path, node.lineno, rule_label="Performance: Non-Idiomatic range(len(...))")
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
                        ctx = _extract_code_context(self.file_path, sub_child.lineno, rule_label=f"Performance: Redundant {cname} in Loop")
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
            ctx = _extract_code_context(self.file_path, node.lineno, rule_label="Maintainability: Bare Except Clause")
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
            ctx = _extract_code_context(self.file_path, node.lineno, rule_label="Maintainability: Suppressed Exception")
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
            ctx = _extract_code_context(self.file_path, node.lineno, rule_label=f"Security: Dynamic Code Execution ({func_name})")
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
            ctx = _extract_code_context(self.file_path, node.lineno, rule_label="Security: Weak Hash MD5")
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
            ctx = _extract_code_context(self.file_path, node.lineno, rule_label="Maintainability: Unmanaged File Resource")
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
                        ctx = _extract_code_context(self.file_path, node.lineno, rule_label="Security: SQL Injection")
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
                            ctx = _extract_code_context(self.file_path, node.lineno, rule_label="Security: Hardcoded Secret")
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


def run_ast_scan(target_dir: str, target_file: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Scans python files in target_dir (or a specific target_file) using pure Python AST (<100ms deterministic pass).
    Performs immediate Syntax Validation before AST traversal, then checks for Maintainability,
    Efficiency bottlenecks, Logical risks, and Security flaws.
    """
    findings = []
    root_path = Path(target_dir)

    if target_file:
        full_path = Path(target_dir) / target_file if not os.path.isabs(target_file) else Path(target_file)
        if full_path.suffix.lower() != ".py" or not full_path.exists():
            return []
        py_files = [full_path]
    else:
        py_files = list(root_path.rglob("*.py"))

    for py_file in py_files:
        rel_file = py_file.relative_to(root_path).as_posix()
        try:
            with open(py_file, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
        except Exception:
            continue

        # 1. Syntax Validation: Catch syntax errors immediately before running AST traversal
        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError as e:
            line_no = e.lineno or 1
            ctx = _extract_code_context(str(py_file), line_no, rule_label="Syntax Error: Code Parse Failure")
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

        visitor = ASTAuditorVisitor(str(py_file), target_dir)
        visitor.visit(tree)

        for item in visitor.findings:
            item["id"] = f"AST-{len(findings) + 301}"
            item["file"] = rel_file
            item["absolute_path"] = str(py_file)
            findings.append(item)

    return findings


def get_codebase_verbal_rating(score: int) -> Dict[str, Any]:
    """Translates a numeric health score into intuitive verbal ratings and executive verdicts."""
    if score >= 95:
        return {
            "label": "Pristine & Production-Ready",
            "short_label": "Perfect / Pristine",
            "grade": "A+",
            "badge": "💎 Pristine",
            "color": "#10b981",
            "bg_color": "rgba(16, 185, 129, 0.12)",
            "border_color": "#10b981",
            "description": "Codebase is extraordinarily clean, robust, and exhibits zero critical security flaws. Fully ready for production deployment."
        }
    elif score >= 80:
        return {
            "label": "Solid & Stable",
            "short_label": "Fine / Solid",
            "grade": "A",
            "badge": "🟢 Solid & Reliable",
            "color": "#38bdf8",
            "bg_color": "rgba(56, 189, 248, 0.12)",
            "border_color": "#38bdf8",
            "description": "Strong architectural foundation with minor non-blocking items or code smells. Safe for production with standard reviews."
        }
    elif score >= 60:
        return {
            "label": "Fair — Moderate Risk",
            "short_label": "Moderate / Needs Review",
            "grade": "B",
            "badge": "🟡 Moderate Risk",
            "color": "#f59e0b",
            "bg_color": "rgba(245, 158, 11, 0.12)",
            "border_color": "#f59e0b",
            "description": "Noticeable security exposures or elevated cyclomatic complexity. Polish and targeted refactoring recommended before release."
        }
    elif score >= 40:
        return {
            "label": "Degraded — High Vulnerability",
            "short_label": "Poor / Fragile",
            "grade": "C",
            "badge": "🟠 High Debt & Risk",
            "color": "#f97316",
            "bg_color": "rgba(249, 115, 22, 0.12)",
            "border_color": "#f97316",
            "description": "Multiple high-severity security leaks or unmanaged resources present. Unsafe to merge without remediation."
        }
    else:
        return {
            "label": "Critical Failure — Unsafe for Production",
            "short_label": "Critical Alert / Unsafe",
            "grade": "F",
            "badge": "🔴 Critical Failure",
            "color": "#ef4444",
            "bg_color": "rgba(239, 68, 68, 0.12)",
            "border_color": "#ef4444",
            "description": "Immediate intervention required! Contains critical vulnerabilities (e.g. SQL Injection, hardcoded secrets, weak crypto) that jeopardize repository integrity."
        }


def run_web_code_scan(target_dir: str, target_file: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Analyzes JavaScript, TypeScript, and HTML files for security vulnerabilities,
    functional syntax errors, and DOM bugs.
    """
    import re
    findings = []
    root_path = Path(target_dir)

    target_extensions = {".js", ".jsx", ".ts", ".tsx", ".html"}
    ignore_dirs = {".git", "node_modules", "dist", "build", ".venv", "venv"}

    target_paths = []
    if target_file:
        candidate = Path(target_dir) / target_file if not os.path.isabs(target_file) else Path(target_file)
        if candidate.suffix.lower() in target_extensions and candidate.exists():
            target_paths = [candidate]
        else:
            return []
    else:
        for root, dirs, files in os.walk(root_path):
            dirs[:] = [d for d in dirs if d not in ignore_dirs and not d.startswith(".")]
            for file in files:
                fp = Path(root) / file
                if fp.suffix.lower() in target_extensions:
                    target_paths.append(fp)

    for fp in target_paths:
        try:
            rel_file = fp.relative_to(root_path).as_posix()
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for idx, line in enumerate(lines):
                ln = idx + 1

                # 1. Syntax / Malformed function call (e.g. initSmoothScrol};)
                if re.search(r"^\s*([a-zA-Z0-9_$]+)\s*\};", line):
                    ctx = _extract_code_context(str(fp), ln, rule_label="Syntax Error: Malformed Function Call")
                    findings.append({
                        "id": f"WEB-{len(findings) + 401}",
                        "file": rel_file,
                        "absolute_path": str(fp),
                        "line": ln,
                        "rule_id": "FUNC-SYNTAX-ERROR",
                        "category": "Functional",
                        "severity": "Critical",
                        "title": "Syntax Error: Incomplete Function Call in Event Callback",
                        "vulnerable_code": ctx["target_line"],
                        "context_snippet": ctx["snippet"],
                        "highlighted_context": ctx["highlighted_context"],
                        "tool": "web_auditor"
                    })

                # 2. DOM XSS via innerHTML / outerHTML / document.write
                elif re.search(r"\.(innerHTML|outerHTML)\s*=", line) or re.search(r"\bdocument\.write\s*\(", line):
                    ctx = _extract_code_context(str(fp), ln, rule_label="Security: Unsanitized DOM Injection")
                    findings.append({
                        "id": f"WEB-{len(findings) + 401}",
                        "file": rel_file,
                        "absolute_path": str(fp),
                        "line": ln,
                        "rule_id": "SEC-DOM-XSS",
                        "category": "Security",
                        "severity": "High",
                        "title": "DOM-Based Cross-Site Scripting (XSS) via innerHTML",
                        "vulnerable_code": ctx["target_line"],
                        "context_snippet": ctx["snippet"],
                        "highlighted_context": ctx["highlighted_context"],
                        "tool": "web_auditor"
                    })

                # 3. Null reference / Operator precedence bug
                elif re.search(r"([a-zA-Z0-9_$]+)\s*&&\s*\1\.[a-zA-Z0-9_$]+\s*===.*\|\|\s*\1\.[a-zA-Z0-9_$]+", line):
                    ctx = _extract_code_context(str(fp), ln, rule_label="Functional: Null Reference Precedence Risk")
                    findings.append({
                        "id": f"WEB-{len(findings) + 401}",
                        "file": rel_file,
                        "absolute_path": str(fp),
                        "line": ln,
                        "rule_id": "FUNC-NULL-DEREF",
                        "category": "Functional",
                        "severity": "Medium",
                        "title": "Potential Null Reference Exception in Logical Condition",
                        "vulnerable_code": ctx["target_line"],
                        "context_snippet": ctx["snippet"],
                        "highlighted_context": ctx["highlighted_context"],
                        "tool": "web_auditor"
                    })

                # 4. Dangerous eval() execution
                elif re.search(r"\beval\s*\(", line):
                    ctx = _extract_code_context(str(fp), ln, rule_label="Security: Dynamic Code Execution")
                    findings.append({
                        "id": f"WEB-{len(findings) + 401}",
                        "file": rel_file,
                        "absolute_path": str(fp),
                        "line": ln,
                        "rule_id": "SEC-DYNAMIC-EVAL",
                        "category": "Security",
                        "severity": "Critical",
                        "title": "Arbitrary Code Execution via eval()",
                        "vulnerable_code": ctx["target_line"],
                        "context_snippet": ctx["snippet"],
                        "highlighted_context": ctx["highlighted_context"],
                        "tool": "web_auditor"
                    })

                # 5. Hardcoded API secrets in frontend code
                elif re.search(r"(api_key|apiKey|secret|token|auth_token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", line, re.I):
                    ctx = _extract_code_context(str(fp), ln, rule_label="Security: Hardcoded Token in Frontend")
                    findings.append({
                        "id": f"WEB-{len(findings) + 401}",
                        "file": rel_file,
                        "absolute_path": str(fp),
                        "line": ln,
                        "rule_id": "SEC-EXPOSED-SECRET",
                        "category": "Security",
                        "severity": "High",
                        "title": "Hardcoded Secret Token Exposed in Client-Side Code",
                        "vulnerable_code": ctx["target_line"],
                        "context_snippet": ctx["snippet"],
                        "highlighted_context": ctx["highlighted_context"],
                        "tool": "web_auditor"
                    })
        except Exception:
            continue

    return findings


def clean_rule_metadata(item: Dict[str, Any]) -> Dict[str, Any]:
    """Cleans technical linter names (bandit, radon, ast) into authoritative, plain English descriptors and ensures schema consistency."""
    rule_id = item.get("rule_id", "").lower()
    title = item.get("title", "")
    category = item.get("category", "Security")

    # Synchronize line_no and before_code
    if "line_no" not in item and "line" in item:
        item["line_no"] = item["line"]
    elif "line" not in item and "line_no" in item:
        item["line"] = item["line_no"]

    if "before_code" not in item and "vulnerable_code" in item:
        item["before_code"] = item["vulnerable_code"]
    elif "vulnerable_code" not in item and "before_code" in item:
        item["vulnerable_code"] = item["before_code"]

    if "explanation" not in item or not item["explanation"]:
        item["explanation"] = f"{title}. Immediate refactoring recommended to uphold repository standards."

    if "b201" in rule_id or "flask_debug" in rule_id:
        item["title"] = "Flask Interactive Debug Mode Enabled in Production"
        item["rule_id"] = "SEC-DEBUG-PRODUCTION"
    elif "b104" in rule_id:
        item["title"] = "Wildcard Network Interface Binding (0.0.0.0)"
        item["rule_id"] = "SEC-INTERFACE-BIND"
    elif any(k in rule_id for k in ["b105", "b106", "b107", "hardcoded-secret"]):
        item["title"] = "Hardcoded Authentication Credential or Secret Key"
        item["rule_id"] = "SEC-HARDCODED-SECRET"
    elif "b608" in rule_id or "sql" in rule_id:
        item["title"] = "SQL Injection Vulnerability via Formatted Query Construction"
        item["rule_id"] = "SEC-SQL-INJECTION"
    elif any(k in rule_id for k in ["b324", "b303", "md5"]):
        item["title"] = "Cryptographically Broken MD5 Hashing Algorithm"
        item["rule_id"] = "SEC-WEAK-HASHING"
    elif "b307" in rule_id or "eval" in rule_id:
        item["title"] = "Arbitrary Dynamic Code Execution via eval()"
        item["rule_id"] = "SEC-DYNAMIC-EVAL"
    elif any(k in rule_id for k in ["b602", "b603", "shell"]):
        item["title"] = "Command Injection Risk via Subprocess Shell Execution"
        item["rule_id"] = "SEC-COMMAND-INJECTION"
    elif "b506" in rule_id:
        item["title"] = "Unsafe YAML Deserialization via yaml.load()"
        item["rule_id"] = "SEC-UNSAFE-DESERIALIZATION"
    elif "complexity" in rule_id or "radon" in rule_id:
        clean_name = re.sub(r"(?i)radon:complexity:\s*", "", title)
        item["title"] = clean_name if "Complexity" in clean_name else "Excessive Cyclomatic Complexity in Business Logic"
        item["rule_id"] = "MAINT-COMPLEXITY-DEBT"
    elif "unclosed-resource" in rule_id:
        item["title"] = "Unmanaged File Resource Handle (Missing Context Manager)"
        item["rule_id"] = "MAINT-UNCLOSED-HANDLE"
    
    # Strip any remaining technical prefixes
    clean_title = re.sub(r"(?i)\b(bandit|radon|ast_engine|ast_visitor|sast)\b:?", "", item.get("title", "")).strip(" :-_")
    if clean_title:
        item["title"] = clean_title

    # Set user-facing engine descriptor without exposing underlying CLI tools
    if category == "Security":
        item["tool"] = "Security Vulnerability Engine"
    elif category == "Performance":
        item["tool"] = "Performance Optimization Engine"
    elif category == "Maintainability":
        item["tool"] = "Code Maintainability Engine"
    elif category == "Quality":
        item["tool"] = "Code Quality & Logic Engine"
    else:
        item["tool"] = "Quality Engine"

    return item


def analyze_repository(target_dir: str, target_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Orchestrates the comprehensive multi-language scan across Python, JavaScript, TypeScript, and Web code.
    Can analyze the entire repository/directory or target a single specific file.
    Merges and deduplicates findings into a clean standardized schema.
    """
    normalized_target_file = None
    if target_file:
        if os.path.isabs(target_file):
            try:
                normalized_target_file = os.path.relpath(target_file, target_dir).replace("\\", "/")
            except ValueError:
                normalized_target_file = Path(target_file).name
        else:
            normalized_target_file = Path(target_file).as_posix()

    bandit_results = run_bandit_scan(target_dir, target_file=normalized_target_file)
    radon_results = run_radon_complexity_scan(target_dir, target_file=normalized_target_file)
    ast_results = run_ast_scan(target_dir, target_file=normalized_target_file)
    web_results = run_web_code_scan(target_dir, target_file=normalized_target_file)

    all_raw = bandit_results + radon_results + ast_results + web_results
    all_findings = []
    seen_keys = set()

    for item in all_raw:
        item = clean_rule_metadata(item)
        item_file = item.get("file", "").replace("\\", "/")
        if normalized_target_file and item_file != normalized_target_file and not item_file.endswith("/" + normalized_target_file):
            continue
        key = (item["file"], item["line"], item["category"])
        if key not in seen_keys:
            seen_keys.add(key)
            all_findings.append(item)

    # Calculate severity counts
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in all_findings:
        sev = f.get("severity", "Low")
        if sev in counts:
            counts[sev] += 1

    # Formula: Score = 100 - (20*Critical + 10*High + 5*Medium + 2*Low)
    deductions = (20 * counts["Critical"]) + (10 * counts["High"]) + (5 * counts["Medium"]) + (2 * counts["Low"])
    health_score = max(0, 100 - deductions)
    verbal_rating = get_codebase_verbal_rating(health_score)

    return {
        "summary": {
            "health_score": health_score,
            "verbal_rating": verbal_rating,
            "total_issues": len(all_findings),
            "critical": counts["Critical"],
            "high": counts["High"],
            "medium": counts["Medium"],
            "low": counts["Low"],
            "security_count": sum(1 for f in all_findings if f.get("category") == "Security"),
            "quality_count": sum(1 for f in all_findings if f.get("category") in {"Quality", "Maintainability", "Performance", "Functional"}),
            "maintainability_count": sum(1 for f in all_findings if f.get("category") in {"Maintainability", "Functional"}),
            "performance_count": sum(1 for f in all_findings if f.get("category") == "Performance"),
            "deductions": deductions,
            "scope": "file" if normalized_target_file else "repo",
            "target_file": normalized_target_file,
            "target_dir": target_dir
        },
        "findings": all_findings
    }

