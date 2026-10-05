#!/usr/bin/env python3
"""
analyze.py - enriches suggestions.json using a free-tier LLM API
(Groq by default, or any other OpenAI-compatible /chat/completions endpoint).

Reads the output of parse_nmap.py and asks the model for:
  1. A richer, context-aware analysis + command list per open port.
  2. An overall risk-priority ordering and a short attack-path narrative.

Requires an API key in the AI_API_KEY environment variable.

Usage:
    export AI_API_KEY="your_key_here"
    python3 analyze.py <suggestions.json> --out <suggestions_ai.json>

ONLY use this against targets you are explicitly authorized to test.
Scan data (ports, service names, versions) is sent to the configured
external API provider when this script runs.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

DEFAULT_API_BASE = "https://api.groq.com/openai/v1"
DEFAULT_MODEL = "llama-3.1-8b-instant"

SYSTEM_PROMPT = (
    "You are a precise security analysis assistant helping with an "
    "authorized penetration test in a lab/CTF environment. "
    "Always reply with strict JSON only, no markdown fences, no commentary "
    "outside the JSON object."
)


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input_path", help="Path to suggestions.json (from parse_nmap.py)")
    p.add_argument("--out", required=True, help="Path to write the enriched JSON")
    p.add_argument("--api-base", default=os.environ.get("AI_API_BASE", DEFAULT_API_BASE),
                    help="OpenAI-compatible API base URL")
    p.add_argument("--model", default=os.environ.get("AI_MODEL", DEFAULT_MODEL),
                    help="Model name to use")
    p.add_argument("--timeout", type=int, default=60, help="Request timeout in seconds")
    return p.parse_args()


def load_data(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def build_prompt(data):
    """Turns the parsed scan data into a plain-text summary for the model."""
    lines = [f"Target: {data.get('target', 'unknown')}"]
    for host in data.get("hosts", []):
        lines.append(f"Host {host.get('address', 'unknown')}:")
        for p in host.get("open_ports", []):
            lines.append(
                f"  - port {p['port']}/{p.get('protocol', 'tcp')} "
                f"service={p.get('service', 'unknown')} "
                f"product={p.get('product', '')} "
                f"version={p.get('version', '')}"
            )
    summary = "\n".join(lines)

    schema = """{
  "ports": {
    "<port_number_as_string>": {
      "analysis": "short explanation of this service's relevance/risk",
      "recommended_commands": ["command1", "command2"]
    }
  },
  "overall": {
    "priority_order": [<port_number>, <port_number>],
    "attack_path": "short narrative on the most promising path to test first and why"
  }
}"""

    return (
        "Given the following nmap scan results, respond with STRICT JSON only, "
        f"matching exactly this schema:\n\n{schema}\n\nScan results:\n{summary}"
    )


def call_llm(prompt, api_key, api_base, model, timeout):
    """Sends a chat completion request to an OpenAI-compatible endpoint."""
    url = f"{api_base}/chat/completions"
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }
    data = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {api_key}")

    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8")

    payload = json.loads(raw)
    return payload["choices"][0]["message"]["content"]


def extract_json(text):
    """Strips accidental markdown fences and parses the model's reply as JSON."""
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    return json.loads(text.strip())


def merge_ai_results(data, ai_result):
    """Attaches the AI's per-port analysis and overall assessment onto data."""
    ports_info = ai_result.get("ports", {})
    for host in data.get("hosts", []):
        for p in host.get("open_ports", []):
            key = str(p["port"])
            if key in ports_info:
                p["ai_analysis"] = ports_info[key].get("analysis", "")
                p["ai_recommended_commands"] = ports_info[key].get("recommended_commands", [])
    data["ai_overall"] = ai_result.get("overall", {})
    return data


def main():
    args = parse_args()

    api_key = os.environ.get("AI_API_KEY")
    if not api_key:
        print("[ai] AI_API_KEY environment variable not set. Skipping AI enrichment.", file=sys.stderr)
        sys.exit(1)

    try:
        data = load_data(args.input_path)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"[ai] Could not read {args.input_path}: {exc}", file=sys.stderr)
        sys.exit(1)

    prompt = build_prompt(data)

    try:
        raw_reply = call_llm(prompt, api_key, args.api_base, args.model, args.timeout)
        ai_result = extract_json(raw_reply)
    except urllib.error.HTTPError as exc:
        print(f"[ai] API returned an error: {exc.code} {exc.reason}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(f"[ai] Network error reaching {args.api_base}: {exc}", file=sys.stderr)
        sys.exit(1)
    except (json.JSONDecodeError, KeyError, IndexError) as exc:
        print(f"[ai] Could not parse model response as the expected JSON: {exc}", file=sys.stderr)
        sys.exit(1)

    enriched = merge_ai_results(data, ai_result)

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(enriched, fh, indent=2, ensure_ascii=False)

    print(f"[ai] Enriched suggestions saved to {args.out}")


if __name__ == "__main__":
    main()