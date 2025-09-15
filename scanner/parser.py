import os
import sys
import logging
import platform
import subprocess
import tempfile
import csv
import shutil
from pathlib import Path

# --- Basic Setup ---
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Global State & Configuration ---

CODEQL_AVAILABLE = False

SKIP_DIRS = {
    ".git", "build", "tests", "test", "testing", "examples", "example", "docs", "doc",
    "benchmark", "third_party", "external", "contrib", "tools"
}
SKIP_DIR_PREFIXES = (".")

def _is_path_in_skipped_dir(file_path: str, repo_root: str) -> bool:
    try:
        relative_path = Path(file_path).relative_to(repo_root)
        path_parts = {part.lower() for part in relative_path.parts}
        if any(part in SKIP_DIRS for part in path_parts):
            return True
        if any(part.startswith(SKIP_DIR_PREFIXES) for part in relative_path.parts if part not in ('.', '..')):
            return True
    except (ValueError, TypeError):
        pass
    return False

def _initialize_codeql_cli():
    global CODEQL_AVAILABLE
    try:
        subprocess.run(
            ["codeql", "--version"],
            check=True,
            capture_output=True,
            text=True
        )
        logger.info("CodeQL CLI found and accessible.")
        CODEQL_AVAILABLE = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.warning("CodeQL CLI not found. Ensure 'codeql' is in your system's PATH to use CodeQL features.")
        CODEQL_AVAILABLE = False

def _create_codeql_database(repo_path: str, db_path: str) -> bool:
    """Creates a CodeQL database for a C/C++ repository."""
    if os.path.exists(db_path):
        logger.info(f"CodeQL database already exists at {db_path}. Skipping creation.")
        return True

    repo_name = os.path.basename(os.path.normpath(repo_path))
    logger.info(f"Creating CodeQL database for '{repo_name}' at {db_path}...")

    command = [
        "codeql", "database", "create", db_path,
        "--language=c-cpp",
        f"--source-root={repo_path}"
                ]

    try:
        subprocess.run(
            command,
            check=True,
            cwd=repo_path
        )
        logger.info(f"Successfully created CodeQL database at: {db_path}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Failed to create CodeQL database.")
        logger.error(f"Command failed with exit code {e.returncode}")
        logger.error(f"Stderr:\n{e.stderr}")
        return False

def _run_and_process_query(db_path: str, repo_path: str) -> list[dict]:
    query_file_path = os.path.join((os.path.dirname(os.path.abspath(__file__))), "query", "query.ql")
    bqrs_path = os.path.join(repo_path, "results.bqrs")
    csv_path = os.path.join(repo_path, "results.csv")

    if not os.path.exists(query_file_path):
        logger.error(f"Query file '{query_file_path}' does not exist. Ensure the query is available.")
        return []

    logger.info("Running CodeQL query to extract function declarations...")
    run_command = [
        "codeql", "query", "run",
        f"--database={db_path}",
        f"--output={bqrs_path}",
        query_file_path
    ]

    try:
        subprocess.run(run_command, check=True, capture_output=True, text=True)
        logger.info(f"Query completed. Results written to: {bqrs_path}")
    except subprocess.CalledProcessError as e:
        logger.error(f"CodeQL query failed:\n{e.stderr}")
        return []

    # Decode BQRS to CSV
    decode_command = [
        "codeql", "bqrs", "decode",
        "--format=csv",
        f"--output={csv_path}",
        bqrs_path
    ]

    try:
        subprocess.run(decode_command, check=True, capture_output=True, text=True)
        logger.info(f"Decoded BQRS to CSV: {csv_path}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to decode BQRS file:\n{e.stderr}")
        return []

    return _parse_results_csv(csv_path, repo_path)

def _parse_results_csv(csv_path: str, repo_path: str) -> list[dict]:
    functions = []
    processed_signatures = set()

    if not os.path.exists(csv_path):
        logger.warning("Query result file not found.")
        return []

    with open(csv_path, 'r', newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            file_path = row['filePath']

            if _is_path_in_skipped_dir(file_path, repo_path):
                continue

            params = [p.strip() for p in row['parameterString'].split(',') if p.strip()]
            ns = row['namespace']
            func_name = row['functionName']
            full_name = f"{ns}::{func_name}" if ns else func_name
            signature = f"{full_name}({','.join(params)})"

            if signature not in processed_signatures:
                function_info = {
                    "name":        func_name,
                    "namespace":   ns or None,
                    "full_name":   full_name,
                    "return_type": row['returnType'],
                    "parameters":  params,
                    "filepath":    file_path,
                    "line":        int(row['startLine'])
                }
                functions.append(function_info)
                processed_signatures.add(signature)

    return functions

def parse_repo_headers_with_codeql(repo_path: str) -> list[dict]:
    """
    Analyzes a C++ repository using CodeQL to extract public function declarations.

    Args:
        repo_path: The absolute path to the root of the repository.

    Returns:
        A list of dictionaries, where each dictionary represents a unique function declaration.
    """
    if not CODEQL_AVAILABLE:
        logger.error("Cannot parse repository because CodeQL CLI is not available or not found in PATH.")
        return []

    repo_path = os.path.abspath(repo_path)
    repo_name = os.path.basename(repo_path)
    db_path = os.path.join(repo_path, f"{repo_name}.db")

    if not _create_codeql_database(repo_path, db_path):
        return []

    all_functions = _run_and_process_query(db_path, repo_path)

    logger.info(f"Finished parsing '{repo_name}'. Extracted {len(all_functions)} unique function declarations.")
    return all_functions

# --- Initialization ---
_initialize_codeql_cli()
