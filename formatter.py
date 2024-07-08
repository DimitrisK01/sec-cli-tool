def format_gitleaks_findings(findings):
    """Format Gitleaks findings for better readability."""
    formatted_findings = []
    for finding in findings:
        # Safely access each key with a default value if the key is not present
        description = finding.get('Description', 'No description provided')
        file = finding.get('File', 'No file specified')
        line = finding.get('Line', 'No line number')
        secret = finding.get('Secret', 'No secret found')
        match = finding.get('Match', 'No match details')
        rule_id = finding.get('RuleID', 'No rule ID')

        # Format the finding into a readable string
        formatted_finding = (
            f"Description: {description}\n"
            f"File: {file}\n"
            f"Line: {line}\n"
            f"Secret: {secret}\n"
            f"Match: {match}\n"
            f"RuleID: {rule_id}\n"
            "----------------------------------------"
        )
        formatted_findings.append(formatted_finding)
    return "\n\n".join(formatted_findings)

def append_to_report(report_contents, scanner_output, scan_type):
    if scanner_output:
        report_section = f"\n==== {scan_type} Scan ====\n" + scanner_output
        return report_contents + report_section
    return report_contents
