"""
Sample report generation service with intentional code quality & maintainability issues.
"""

def generate_user_report(user_type: str, region: str, tier: int, is_active: bool, has_discount: bool, role: str):
    """
    QUALITY ISSUE: Excessively high cyclomatic complexity (Radon Grade D/F, CC > 12).
    Deeply nested if-else branches make this function fragile and untestable.
    """
    report_title = "Standard Report"
    discount_rate = 0.0

    if is_active:
        if region == "US":
            if user_type == "enterprise":
                if tier == 1:
                    discount_rate = 0.25
                elif tier == 2:
                    discount_rate = 0.15
                else:
                    discount_rate = 0.05
            elif user_type == "smb":
                if has_discount:
                    if role == "admin":
                        discount_rate = 0.20
                    else:
                        discount_rate = 0.10
                else:
                    discount_rate = 0.02
            else:
                discount_rate = 0.0
        elif region == "EU":
            if user_type == "enterprise":
                if tier == 1:
                    discount_rate = 0.30
                else:
                    discount_rate = 0.12
            else:
                if has_discount:
                    discount_rate = 0.08
        elif region == "APAC":
            if tier > 3:
                discount_rate = 0.05
            else:
                discount_rate = 0.10
        else:
            discount_rate = 0.0
    else:
        discount_rate = 0.0

    return {
        "title": report_title,
        "discount_rate": discount_rate
    }


def unclosed_resource_leak(filename: str):
    """
    QUALITY/MAINTAINABILITY ISSUE: Unclosed file handle without context manager (with).
    """
    f = open(filename, "r")
    data = f.read()
    # Missing f.close() or context manager
    return data
