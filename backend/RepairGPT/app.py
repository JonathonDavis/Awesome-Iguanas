import os
import time
import json
from typing import Any, Dict, List, Optional

import requests
from flask import Flask, jsonify, request
from neo4j import GraphDatabase


def _env(*names: str, default: Optional[str] = None) -> Optional[str]:
    for name in names:
        value = os.environ.get(name)
        if value is not None and str(value).strip() != "":
            return value
    return default


def _neo4j_driver():
    uri = _env("NEO4J_URI", "VITE_NEO4J_URI", default="neo4j://localhost:7687")
    user = _env("NEO4J_USERNAME", "NEO4J_USER", "VITE_NEO4J_USER", default="neo4j")
    password = _env("NEO4J_PASSWORD", "VITE_NEO4J_PASSWORD", default="")
    database = _env("NEO4J_DATABASE", "VITE_NEO4J_DATABASE")

    driver = GraphDatabase.driver(uri, auth=(user, password))
    return driver, database


def _ollama_base_url() -> str:
    # In docker-compose the hostname is typically the service name: ollama
    return _env("OLLAMA_BASE_URL", default="http://ollama:11434")


def _ollama_pull(model: str, timeout_s: int = 3600) -> None:
    url = f"{_ollama_base_url().rstrip('/')}/api/pull"
    payload: Dict[str, Any] = {
        "name": model,
        "stream": False,
    }
    resp = requests.post(url, json=payload, timeout=timeout_s)
    resp.raise_for_status()


def _ollama_chat(model: str, messages: List[Dict[str, str]], timeout_s: int = 600) -> str:
    url = f"{_ollama_base_url().rstrip('/')}/api/chat"
    payload: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": 0.1,
        },
    }

    resp = requests.post(url, json=payload, timeout=timeout_s)
    if resp.status_code == 404:
        # Ollama uses 404 when the requested model isn't available locally.
        # Attempt to pull the model once, then retry the chat.
        try:
            err = resp.json().get("error", "")
        except Exception:
            err = resp.text or ""

        if "model" in err and "not found" in err:
            _ollama_pull(model)
            resp = requests.post(url, json=payload, timeout=timeout_s)

    resp.raise_for_status()
    data = resp.json()
    return (data.get("message") or {}).get("content") or ""


def _parse_findings(raw: str) -> List[Dict[str, Any]]:
    if not raw or not raw.strip():
        return []

    # Try strict JSON first.
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict) and isinstance(parsed.get("vulnerabilities"), list):
            return parsed["vulnerabilities"]
        if isinstance(parsed, list):
            return parsed
    except json.JSONDecodeError:
        pass

    # Attempt to extract JSON object/array embedded in text.
    start_candidates = [raw.find("{"), raw.find("[")]
    start_candidates = [i for i in start_candidates if i != -1]
    if start_candidates:
        start = min(start_candidates)
        for end in range(len(raw) - 1, start, -1):
            if raw[end] in ["}", "]"]:
                snippet = raw[start : end + 1]
                try:
                    parsed = json.loads(snippet)
                    if isinstance(parsed, dict) and isinstance(parsed.get("vulnerabilities"), list):
                        return parsed["vulnerabilities"]
                    if isinstance(parsed, list):
                        return parsed
                except json.JSONDecodeError:
                    continue

    # Fallback: store as one finding.
    return [
        {
            "headline": "LLM output (unparsed)",
            "analysis": raw[:65000],
            "most_relevant_cve_cwe": "N/A",
            "most_concerned_functions": [],
            "most_concerned_filenames": [],
            "classification": "N/A",
        }
    ]


def _normalize_finding(f: Dict[str, Any]) -> Dict[str, str]:
    headline = str(f.get("headline") or "").strip()
    analysis = str(f.get("analysis") or "").strip()

    cve_ref = (
        f.get("most_relevant_cve_cwe")
        or f.get("most_relevant_cve")
        or f.get("cve_reference")
        or f.get("cve")
        or ""
    )
    cve_ref = str(cve_ref).strip()

    key_functions = f.get("most_concerned_functions") or f.get("key_functions") or []
    if isinstance(key_functions, list):
        key_functions_str = ", ".join([str(x) for x in key_functions if x is not None])
    else:
        key_functions_str = str(key_functions)

    key_filenames = f.get("most_concerned_filenames") or f.get("key_filenames") or []
    if isinstance(key_filenames, list):
        key_filenames_str = ", ".join([str(x) for x in key_filenames if x is not None])
    else:
        key_filenames_str = str(key_filenames)

    classification = str(f.get("classification") or "N/A").strip()

    remediation_steps = f.get("remediation_steps") or f.get("remediation") or f.get("fix") or []
    remediation_text = ""
    if isinstance(remediation_steps, list):
        steps = [str(x).strip() for x in remediation_steps if x is not None and str(x).strip()]
        if steps:
            remediation_text = "\n".join([f"- {s}" for s in steps])
    else:
        remediation_text = str(remediation_steps).strip()

    if not headline:
        headline = "Unnamed Finding"
    if not analysis:
        analysis = "No analysis available"

    # Ensure the UI shows fix guidance even if it only renders `analysis`.
    if remediation_text and "remediation" not in analysis.lower() and "fix" not in analysis.lower():
        analysis = f"{analysis}\n\nRemediation:\n{remediation_text}"

    return {
        "headline": headline,
        "analysis": analysis,
        "cve_reference": cve_ref,
        "key_functions": key_functions_str,
        "key_filenames": key_filenames_str,
        "classification": classification,
    }


def _fetch_repo_vulnerabilities(session, repo_url: str, limit_vulns: int) -> List[Dict[str, Any]]:
    limit_clause = "LIMIT $limit" if limit_vulns and int(limit_vulns) > 0 else ""
    rows = session.run(
        f"""
        MATCH (r:Repository {{url: $repo_url}})-[:HAS_VULNERABILITY]->(v:Vulnerability)
        OPTIONAL MATCH (c:CVE)-[:IDENTIFIED_AS]->(v)
        WITH v,
             v.id AS id,
             v.summary AS summary,
             v.details AS details,
             collect(DISTINCT c.id) AS cves,
             v.modified AS modified
        RETURN id, summary, details, cves
        ORDER BY modified DESC
        {limit_clause}
        """,
        repo_url=repo_url,
        limit=int(limit_vulns) if limit_vulns and int(limit_vulns) > 0 else 0,
    )
    return [
        {
            "id": row.get("id"),
            "summary": row.get("summary"),
            "details": row.get("details"),
            "cves": row.get("cves") or [],
        }
        for row in rows
    ]


def _chunk(items: List[Dict[str, Any]], size: int) -> List[List[Dict[str, Any]]]:
    if size <= 0:
        return [items]
    return [items[i : i + size] for i in range(0, len(items), size)]


def _persist_findings(session, repo_url: str, model: str, findings: List[Dict[str, str]]) -> int:
    if not findings:
        return 0

    # Pick the most recently analyzed version if available (best-effort).
    version_row = session.run(
        """
        MATCH (r:Repository {url: $repo_url})
        OPTIONAL MATCH (r)-[:HAS_VERSION]->(v:Version)
        WITH r, v
        ORDER BY v.analyzed_at DESC
        RETURN v.id AS version_id
        LIMIT 1
        """,
        repo_url=repo_url,
    ).single()
    version_id = version_row.get("version_id") if version_row else None

    created = 0
    now_epoch = int(time.time())

    for idx, finding in enumerate(findings):
        vuln_id = str(finding.get("vulnerability_id") or "").strip()

        # Deterministic ID to avoid duplicates on re-runs.
        if vuln_id:
            finding_id = f"{repo_url}::{model}::{vuln_id}".replace("/", "_")
        else:
            finding_id = f"{repo_url.replace('/', '_')}::{model}::{now_epoch}::{idx}"

        params = {
            "repo_url": repo_url,
            "version_id": version_id,
            "id": finding_id,
            "headline": finding["headline"],
            "analysis": finding["analysis"],
            "cve_reference": finding["cve_reference"],
            "key_functions": finding["key_functions"],
            "key_filenames": finding["key_filenames"],
            "classification": finding["classification"],
            "vulnerability_id": vuln_id,
            "timestamp": now_epoch,
            "source": "DeepSeek",
            "model": model,
        }

        session.run(
            """
            MATCH (r:Repository {url: $repo_url})
            OPTIONAL MATCH (v:Version {id: $version_id})
            MERGE (f:AIVulnerabilityFinding {id: $id})
            SET f.headline = $headline,
                f.analysis = $analysis,
                f.cve_reference = $cve_reference,
                f.key_functions = $key_functions,
                f.key_filenames = $key_filenames,
                f.classification = $classification,
                f.vulnerability_id = $vulnerability_id,
                f.timestamp = $timestamp,
                f.source = $source,
                f.model = $model,
                f.evaluatedAt = datetime()
            MERGE (f)-[:AFFECTS]->(r)
            FOREACH (_ IN CASE WHEN v IS NULL THEN [] ELSE [1] END | MERGE (f)-[:FOUND_IN_VERSION]->(v))
            """,
            **params,
        )
        created += 1

    return created


def _build_prompt(repo_url: str, vulns: List[Dict[str, Any]]) -> str:
    # Keep prompt compact; DeepSeek-R1 can still reason well on summaries.
    vuln_lines: List[str] = []
    for v in vulns:
        cves = ", ".join([c for c in (v.get("cves") or []) if c])
        vuln_lines.append(
            "\n".join(
                [
                    f"- Vulnerability ID: {v.get('id')}",
                    f"  Summary: {v.get('summary') or 'N/A'}",
                    f"  Details: {(v.get('details') or 'N/A')[:800]}",
                    f"  CVEs: {cves or 'N/A'}",
                ]
            )
        )

    expected = len(vulns)

    return (
        "You are VulGPT, an expert security analyst.\n\n"
        f"Repository: {repo_url}\n\n"
        "Given the vulnerability records below, produce an actionable set of findings.\n"
        "Each finding must clearly explain WHAT the issue is, WHY it matters, and HOW to fix/mitigate it.\n\n"
        f"Return EXACTLY {expected} findings (one per vulnerability record, in the same order).\n\n"
        "Return ONLY valid JSON in one of these formats:\n"
        "1) {\"vulnerabilities\": [ ... ]}\n"
        "2) [ ... ]\n\n"
        "Each item must have:\n"
        "- headline (string)\n"
        "- analysis (string; include a short impact explanation)\n"
        "- remediation_steps (array of 2-6 concrete steps; MUST be present)\n"
        "- most_relevant_cve_cwe (string; CVE if available)\n"
        "- most_concerned_functions (array of strings; can be empty)\n"
        "- most_concerned_filenames (array of strings; can be empty)\n"
        "- classification (one of: Very Promising, Slightly Promising, Moderate, Not Promising, N/A)\n\n"
        "Rules:\n"
        "- remediation_steps MUST be specific (e.g., 'upgrade to a fixed version', 'add input validation', 'escape output', 'enable CSP', 'add rate limiting'), not generic.\n"
        "- If the fixed version is not in the records, say to upgrade to the latest patched release line.\n\n"
        "VULNERABILITY RECORDS:\n"
        + "\n\n".join(vuln_lines)
    )


app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.post("/evaluate")
def evaluate():
    body = request.get_json(silent=True) or {}

    model = str(body.get("model") or _env("OLLAMA_MODEL", default="deepseek-r1:7b"))
    limit_repos = int(body.get("limit_repos") or 3)
    limit_vulns = int(body.get("limit_vulns") or 8)
    all_repos = bool(body.get("all_repos") or False)
    all_vulns = bool(body.get("all_vulns") or False)
    chunk_size = int(body.get("chunk_size") or 8)
    repo_url = body.get("repo_url")

    driver, database = _neo4j_driver()

    try:
        session_args = {"database": database} if database else {}
        with driver.session(**session_args) as session:
            if repo_url:
                repo_urls = [repo_url]
            else:
                # Prefer repos that are actually linked to vulnerabilities;
                # ordering by vuln count yields more meaningful LLM output.
                rows = session.run(
                    """
                    MATCH (r:Repository)-[:HAS_VULNERABILITY]->(:Vulnerability)
                    WITH r, count(*) AS vulnCount
                    RETURN r.url AS url
                    ORDER BY vulnCount DESC
                    LIMIT $limit
                    """,
                    limit=10000 if all_repos else max(limit_repos * 3, limit_repos),
                )
                repo_urls = [row.get("url") for row in rows if row.get("url")]

            # Avoid spending forever on first-run.
            repo_urls = [u for u in repo_urls if u != "https://github.com/torvalds/linux"][:limit_repos]

            totals = {"repos": 0, "findings_created": 0}
            per_repo: List[Dict[str, Any]] = []

            for url in repo_urls:
                all_repo_vulns = _fetch_repo_vulnerabilities(session, url, limit_vulns=0 if all_vulns else limit_vulns)
                if not all_repo_vulns:
                    per_repo.append({"repo_url": url, "vulnerabilities": 0, "findings_created": 0, "note": "No vulnerabilities linked to repo"})
                    totals["repos"] += 1
                    continue

                created_total = 0
                for vuln_batch in _chunk(all_repo_vulns, chunk_size if all_vulns else max(chunk_size, len(all_repo_vulns))):
                    prompt = _build_prompt(url, vuln_batch)
                    messages = [
                        {"role": "system", "content": "You are a strict JSON generator. Output JSON only."},
                        {"role": "user", "content": prompt},
                    ]

                    llm_raw = _ollama_chat(model=model, messages=messages)
                    raw_findings = _parse_findings(llm_raw)
                    normalized = [_normalize_finding(f) for f in raw_findings]

                    # Attach the vulnerability_id by position (prompt enforces 1:1 order).
                    for i in range(min(len(normalized), len(vuln_batch))):
                        normalized[i]["vulnerability_id"] = vuln_batch[i].get("id")

                    created_total += _persist_findings(session, url, model=model, findings=normalized)

                per_repo.append(
                    {
                        "repo_url": url,
                        "vulnerabilities": len(all_repo_vulns),
                        "findings_created": created_total,
                    }
                )
                totals["repos"] += 1
                totals["findings_created"] += created_total

            return jsonify({"ok": True, "model": model, "totals": totals, "per_repo": per_repo})
    except requests.RequestException as e:
        return jsonify({"ok": False, "error": f"Ollama request failed: {str(e)}"}), 502
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        driver.close()


if __name__ == "__main__":
    # Bind to 0.0.0.0 for Docker.
    app.run(host="0.0.0.0", port=int(_env("PORT", default="5000")), debug=False)
