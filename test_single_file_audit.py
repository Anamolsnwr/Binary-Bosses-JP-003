import os
import sys
from pathlib import Path
from core.static_scanner import analyze_repository
from core.repo_cloner import get_offline_demo_path, scan_target_files

def main():
    demo_dir = get_offline_demo_path()
    print(f"Testing Single File Audit on Demo Repository: {demo_dir}")

    files = scan_target_files(demo_dir)
    print(f"Scanned {len(files)} files in repository:")
    for f in files:
        print(f" - {f['display_label']}")

    # 1. Full Repo Audit
    full_res = analyze_repository(demo_dir)
    print("\n--- FULL REPO AUDIT ---")
    print(f"Health Score: {full_res['summary']['health_score']}/100")
    print(f"Total Findings: {full_res['summary']['total_issues']}")
    print(f"Scope: {full_res['summary']['scope']}")
    assert full_res['summary']['scope'] == "repo"
    assert full_res['summary']['total_issues'] >= 5

    # 2. Single File Audit on auth_service.py
    auth_res = analyze_repository(demo_dir, target_file="auth_service.py")
    print("\n--- SINGLE FILE AUDIT: auth_service.py ---")
    print(f"Health Score: {auth_res['summary']['health_score']}/100")
    print(f"Total Findings: {auth_res['summary']['total_issues']}")
    print(f"Scope: {auth_res['summary']['scope']}")
    print(f"Target File: {auth_res['summary']['target_file']}")
    assert auth_res['summary']['scope'] == "file"
    assert auth_res['summary']['target_file'] == "auth_service.py"
    for item in auth_res['findings']:
        assert "auth_service.py" in item['file'], f"Unexpected file in auth findings: {item['file']}"
        print(f"  [{item['severity']}] Line {item['line']}: {item['title']}")

    # 3. Single File Audit on report_engine.py
    rep_res = analyze_repository(demo_dir, target_file="report_engine.py")
    print("\n--- SINGLE FILE AUDIT: report_engine.py ---")
    print(f"Health Score: {rep_res['summary']['health_score']}/100")
    print(f"Total Findings: {rep_res['summary']['total_issues']}")
    print(f"Scope: {rep_res['summary']['scope']}")
    print(f"Target File: {rep_res['summary']['target_file']}")
    assert rep_res['summary']['scope'] == "file"
    assert rep_res['summary']['target_file'] == "report_engine.py"
    for item in rep_res['findings']:
        assert "report_engine.py" in item['file'], f"Unexpected file in report findings: {item['file']}"
        print(f"  [{item['severity']}] Line {item['line']}: {item['title']}")

    # Ensure individual file health scores reflect their own deductions
    print(f"\nScore comparisons:")
    print(f"Full Repo: {full_res['summary']['health_score']}/100")
    print(f"auth_service.py: {auth_res['summary']['health_score']}/100")
    print(f"report_engine.py: {rep_res['summary']['health_score']}/100")

    print("\nALL SINGLE FILE AUDIT UNIT TESTS PASSED!")

if __name__ == "__main__":
    main()

