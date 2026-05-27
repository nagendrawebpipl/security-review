#!/usr/bin/env python3
import json
import os
import re
import sys
import time
from pathlib import Path
import anthropic

TEST_INPUTS_PATH = Path(os.environ.get("TEST_INPUTS_PATH", "test_inputs.json"))
RESULTS_PATH     = Path(os.environ.get("RESULTS_PATH",     "results.json"))

REVIEW_PROMPT = (
    "You are an expert application security engineer performing a code security review.\n"
    "Analyse the source files below and produce a structured security report.\n\n"
    "Package: {package_name}\n"
    "Review notes: {review_notes}\n\n"
    "Source files:\n{source_files}\n\n"
    "Perform your analysis in three steps:\n"
    "STEP 1 - Identify: What is the vulnerability type, which file/line is affected?\n"
    "STEP 2 - Impact: What is the realistic exploit scenario and business impact?\n"
    "STEP 3 - Fix: What is the minimal patch that addresses the root cause without broad rewrites?\n\n"
    "Respond ONLY with a JSON object, no markdown fences, no extra text:\n"
    '{{"vulnerability_type": "<sql_injection|hardcoded_secret|path_traversal|weak_auth|unsafe_deserialization|other>", '
    '"affected_file": "<filename>", '
    '"affected_line": "<line number or function name>", '
    '"severity": "<critical|high|medium|low>", '
    '"impact": "<one sentence>", '
    '"exploit_scenario": "<one sentence>", '
    '"root_cause": "<one sentence>", '
    '"patched_files": [{{"filename": "<filename>", "patched_code": "<full patched source>"}}], '
    '"fix_description": "<one sentence>", '
    '"transcript": ['
    '{{"step": "identify", "prompt": "<question>", "finding": "<finding>"}}, '
    '{{"step": "impact", "prompt": "<question>", "finding": "<finding>"}}, '
    '{{"step": "verify", "prompt": "<question>", "finding": "<finding>"}}'
    ']}}'
)

def _call(client, prompt, retries=3):
    for attempt in range(retries):
        try:
            msg = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = msg.content[0].text.strip()
            raw = re.sub(r"^```(?:json)?\s*", "", raw)
            raw = re.sub(r"\s*```$", "", raw)
            return json.loads(raw)
        except (json.JSONDecodeError, anthropic.APIError) as exc:
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
            else:
                raise RuntimeError(f"Claude failed: {exc}") from exc

def format_sources(source_files):
    parts = []
    for f in source_files:
        parts.append(f"### {f['filename']}\n{f['content']}")
    return "\n\n".join(parts)

def process_item(client, item):
    package_name = item.get("package_name", item["id"])
    source_files = item.get("source_files", [])
    review_notes = item.get("review_notes", "Review for security issues.")
    prompt = REVIEW_PROMPT.format(
        package_name=package_name,
        review_notes=review_notes,
        source_files=format_sources(source_files),
    )
    result = _call(client, prompt)
    return {
        "id": item["id"],
        "output": {
            "package_name": package_name,
            "vulnerability_type": result.get("vulnerability_type", "unknown"),
            "affected_file": result.get("affected_file", ""),
            "affected_line": result.get("affected_line", ""),
            "severity": result.get("severity", "high"),
            "impact": result.get("impact", ""),
            "exploit_scenario": result.get("exploit_scenario", ""),
            "root_cause": result.get("root_cause", ""),
            "patched_files": result.get("patched_files", []),
            "fix_description": result.get("fix_description", ""),
            "transcript": result.get("transcript", []),
        },
    }

def main():
    if not TEST_INPUTS_PATH.exists():
        print(f"ERROR: {TEST_INPUTS_PATH} not found", file=sys.stderr)
        sys.exit(1)
    test_inputs = json.loads(TEST_INPUTS_PATH.read_text())
    client      = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))
    results     = []
    total       = len(test_inputs)
    for idx, item in enumerate(test_inputs, 1):
        print(f"[{idx}/{total}] Reviewing {item.get('package_name', item['id'])} ...")
        try:
            result = process_item(client, item)
            results.append(result)
            vuln = result["output"]["vulnerability_type"]
            print(f"  Done - {vuln} in {result['output']['affected_file']}")
        except Exception as exc:
            print(f"  Error: {exc}", file=sys.stderr)
            results.append({
                "id": item["id"],
                "output": {
                    "package_name": item.get("package_name", item["id"]),
                    "vulnerability_type": "unknown",
                    "affected_file": "",
                    "affected_line": "",
                    "severity": "unknown",
                    "impact": "",
                    "exploit_scenario": "",
                    "root_cause": "",
                    "patched_files": [],
                    "fix_description": f"ERROR: {exc}",
                    "transcript": [],
                },
            })
    RESULTS_PATH.write_text(json.dumps(results, indent=2))
    print(f"\nDone - {len(results)} results written to {RESULTS_PATH}")

if __name__ == "__main__":
    main()

