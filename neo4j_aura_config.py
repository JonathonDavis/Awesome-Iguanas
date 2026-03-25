from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional


AURA_TXT_GLOBS = (
    "Neo4j-*-Created-*.txt",
    "Neo4j-*.txt",
)


@dataclass(frozen=True)
class Neo4jConfig:
    uri: str
    username: str
    password: str
    database: Optional[str] = None


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def parse_key_value_env_file(text: str) -> Dict[str, str]:
    env: Dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = _strip_quotes(value)
        if not key:
            continue
        env[key] = value
    return env


def find_aura_env_file(repo_root: Optional[Path] = None) -> Optional[Path]:
    override = os.environ.get("NEO4J_AURA_TXT") or os.environ.get("NEO4J_ENV_FILE")

    if repo_root is None:
        repo_root = Path(__file__).resolve().parent

    if override:
        p = Path(override)
        if not p.is_absolute():
            p = repo_root / p
        if p.exists() and p.is_file():
            return p

    for pattern in AURA_TXT_GLOBS:
        matches = sorted(repo_root.glob(pattern))
        if matches:
            return matches[0]

    return None


def ensure_neo4j_env_loaded(*, force: bool = False) -> Optional[Path]:
    """Load Neo4j Aura credentials from the repo-root TXT file into os.environ.

    Does nothing if required env vars are already present unless force=True.

    Supported keys in the TXT:
      - NEO4J_URI
      - NEO4J_USERNAME
      - NEO4J_PASSWORD
      - NEO4J_DATABASE

    Compatibility aliases written (when missing):
      - NEO4J_USER (from NEO4J_USERNAME)
      - VITE_NEO4J_URI / VITE_NEO4J_USER / VITE_NEO4J_PASSWORD / VITE_NEO4J_DATABASE
        (useful for tools that already expect VITE_* keys).
    """

    has_minimum = bool(
        os.environ.get("NEO4J_URI")
        and (os.environ.get("NEO4J_USERNAME") or os.environ.get("NEO4J_USER"))
        and os.environ.get("NEO4J_PASSWORD")
    )

    if has_minimum and not force:
        return None

    repo_root = Path(__file__).resolve().parent
    env_path = find_aura_env_file(repo_root)
    if not env_path:
        return None

    file_env = parse_key_value_env_file(env_path.read_text(encoding="utf-8"))

    for key, value in file_env.items():
        if force or not os.environ.get(key):
            os.environ[key] = value

    # Compatibility mappings
    if os.environ.get("NEO4J_USERNAME") and (force or not os.environ.get("NEO4J_USER")):
        os.environ["NEO4J_USER"] = os.environ["NEO4J_USERNAME"]

    if os.environ.get("NEO4J_URI") and (force or not os.environ.get("VITE_NEO4J_URI")):
        os.environ["VITE_NEO4J_URI"] = os.environ["NEO4J_URI"]

    if os.environ.get("NEO4J_USER") and (force or not os.environ.get("VITE_NEO4J_USER")):
        os.environ["VITE_NEO4J_USER"] = os.environ["NEO4J_USER"]

    if os.environ.get("NEO4J_PASSWORD") and (force or not os.environ.get("VITE_NEO4J_PASSWORD")):
        os.environ["VITE_NEO4J_PASSWORD"] = os.environ["NEO4J_PASSWORD"]

    if os.environ.get("NEO4J_DATABASE") and (force or not os.environ.get("VITE_NEO4J_DATABASE")):
        os.environ["VITE_NEO4J_DATABASE"] = os.environ["NEO4J_DATABASE"]

    return env_path


def get_neo4j_config() -> Neo4jConfig:
    """Return a Neo4jConfig, auto-loading Aura TXT if needed."""
    ensure_neo4j_env_loaded()

    uri = os.environ.get("NEO4J_URI") or os.environ.get("VITE_NEO4J_URI") or "neo4j://localhost:7687"
    username = (
        os.environ.get("NEO4J_USERNAME")
        or os.environ.get("NEO4J_USER")
        or os.environ.get("VITE_NEO4J_USER")
        or "neo4j"
    )
    password = os.environ.get("NEO4J_PASSWORD") or os.environ.get("VITE_NEO4J_PASSWORD") or ""
    database = os.environ.get("NEO4J_DATABASE") or os.environ.get("VITE_NEO4J_DATABASE")

    return Neo4jConfig(uri=uri, username=username, password=password, database=database)
