"""
Comprehensive test suite for AST Code Quality & Efficiency Engine and LLM Enrichment Schema.
"""
import os
import time
import tempfile
from pathlib import Path
from core.static_scanner import run_ast_scan, analyze_repository
from core.ai_patcher import enrich_code_audit, _get_offline_heuristic_enrichment

SAMPLE_CODE_WITH_ALL_FLAWS = '''
import re

# 1. Parameter Overload (>5 parameters) & Deep Nesting (>=4 levels) & Missing Return
def process_data(a, b, c, d, e, f, opt_param=None):
    if a > 0:
        if b > 0:
            if c > 0:
                if d > 0:
                    val = opt_param.length  # 2. Unchecked None dereference
                    return val
    # Missing return in fallback branch

# 3. Non-idiomatic range(len()) and Redundant operation inside loop
def run_loop(items):
    for i in range(len(items)):
        pat = re.compile(r"^[0-9]+$")  # Redundant invariant call
        print(items[i])

# 4. Dead Code after return
def calc_total(x):
    return x * 2
    print("This is dead code")
    unused_var = 100

# 5. Bare except and Suppressed error
def risky_action():
    try:
        1 / 0
    except:
        pass
'''

SYNTAX_ERROR_CODE = '''
def broken_syntax(
    print("Missing closing paren"
'''

def test_ast_engine_rules_and_speed():
    with tempfile.TemporaryDirectory() as temp_dir:
        # File 1: Code with quality/logic/efficiency flaws
        f1 = Path(temp_dir) / "sample_flaws.py"
        f1.write_text(SAMPLE_CODE_WITH_ALL_FLAWS, encoding="utf-8")

        # File 2: Code with syntax error
        f2 = Path(temp_dir) / "syntax_flaw.py"
        f2.write_text(SYNTAX_ERROR_CODE, encoding="utf-8")

        # Measure deterministic pass execution time (<100ms constraint)
        start_t = time.perf_counter()
        findings = run_ast_scan(temp_dir)
        elapsed_ms = (time.perf_counter() - start_t) * 1000

        print(f"AST Scan Elapsed Time: {elapsed_ms:.2f} ms")
        assert elapsed_ms < 100, f"AST Scan exceeded 100ms constraint: {elapsed_ms:.2f}ms"

        rule_ids = {f["rule_id"] for f in findings}
        print("Detected Rule IDs:", rule_ids)

        # Check all required rules
        assert "QUAL-SYNTAX-ERR" in rule_ids, "Failed to catch syntax error"
        assert "MAINT-PARAM-OVERLOAD" in rule_ids, "Failed to catch parameter overload"
        assert "MAINT-DEEP-NESTING" in rule_ids, "Failed to catch deep nesting"
        assert "LOGIC-UNCHECKED-NONE" in rule_ids, "Failed to catch unchecked None dereference"
        assert "LOGIC-MISSING-RETURN" in rule_ids, "Failed to catch missing return in branch"
        assert "PERF-RANGE-LEN" in rule_ids, "Failed to catch range(len()) non-idiomatic loop"
        assert "PERF-REDUNDANT-LOOP-OP" in rule_ids, "Failed to catch redundant loop operation"
        assert "QUAL-DEAD-CODE" in rule_ids, "Failed to catch dead code following return"
        assert "MAINT-BARE-EXCEPT" in rule_ids or "MAINT-SUPPRESSED-ERR" in rule_ids, "Failed to catch bare/suppressed except"

        # Check enriched schema format
        enrichment = enrich_code_audit(
            file_path=str(f1),
            raw_code=SAMPLE_CODE_WITH_ALL_FLAWS,
            ast_findings=[f for f in findings if f["file"] == "sample_flaws.py"]
        )

        assert "summary" in enrichment, "Missing 'summary' in enrichment output"
        assert "health_score" in enrichment, "Missing 'health_score' in enrichment output"
        assert "detailed_findings" in enrichment, "Missing 'detailed_findings' in enrichment output"
        assert isinstance(enrichment["detailed_findings"], list), "'detailed_findings' must be a list"

        for df in enrichment["detailed_findings"]:
            assert "rule_id" in df, "Finding missing 'rule_id'"
            assert "category" in df, "Finding missing 'category'"
            assert df["category"] in {"Security", "Quality", "Maintainability", "Performance"}, f"Invalid category: {df['category']}"
            assert "line_no" in df, "Finding missing 'line_no'"
            assert "title" in df, "Finding missing 'title'"
            assert "severity" in df, "Finding missing 'severity'"
            assert df["severity"] in {"Critical", "High", "Medium", "Low"}, f"Invalid severity: {df['severity']}"
            assert "explanation" in df, "Finding missing 'explanation'"
            assert "before_code" in df, "Finding missing 'before_code'"
            assert "after_code" in df, "Finding missing 'after_code'"

        print(f"Verified {len(enrichment['detailed_findings'])} enriched findings matching strict JSON schema!")
        print(f"Health score: {enrichment['health_score']}/100")
        print(f"Summary: {enrichment['summary']}")

if __name__ == "__main__":
    test_ast_engine_rules_and_speed()
    print("\nALL AST QUALITY & ENRICHMENT TESTS PASSED!")

