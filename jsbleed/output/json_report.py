"""
JSON report generation for jsbleed
"""

import json
from datetime import datetime


def save_json_report(results, output_path):
    """Save analysis results as a structured JSON report"""
    report = {
        "tool": "jsbleed",
        "version": "1.0.0",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "js_files_analyzed": len(results.get("js_files", [])),
            "secrets_found": len(results.get("secrets", [])),
            "endpoints_found": len(results.get("endpoints", [])),
            "sourcemaps_found": len(results.get("sourcemaps", [])),
            "auth_issues_found": len(results.get("auth_patterns", [])),
            "parameters_found": len(results.get("parameters", [])),
            "critical_findings": sum(
                1 for s in results.get("secrets", []) if s.get("risk") == "CRITICAL"
            ) + sum(
                1 for a in results.get("auth_patterns", []) if a.get("risk") == "CRITICAL"
            ),
        },
        "findings": {
            "secrets": results.get("secrets", []),
            "endpoints": results.get("endpoints", []),
            "sourcemaps": results.get("sourcemaps", []),
            "auth_patterns": results.get("auth_patterns", []),
            "parameters": results.get("parameters", []),
        },
        "js_files": results.get("js_files", []),
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
