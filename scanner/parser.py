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
# Logging will be configured by main.py with colored formatter

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

def _create_codeql_database(repo_path: str, db_path: str, alias: str, build_name: str | None = None, overwrite: bool = False) -> bool:
    """
    Creates a CodeQL database for a C/C++ repository.

    Args:
        repo_path: Path to the repository
        db_path: Path where the CodeQL database will be created
        alias: Repository alias
        build_name: Optional build configuration name (e.g., 'default', 'no-asm')
        overwrite: Whether to overwrite existing database
    """

    repo_name = os.path.basename(os.path.normpath(repo_path))
    build_suffix = f" with build '{build_name}'" if build_name else ""
    logger.info(f"Creating CodeQL database for '{repo_name}' (alias: {alias}{build_suffix}) at {db_path}...")

    # Check if database already exists
    if os.path.exists(db_path):
        if overwrite:
            logger.info(f"Database already exists at {db_path}. Will overwrite (--overwrite-dbs flag is set).")
        else:
            logger.info(f"Database already exists at {db_path}. Skipping creation (use --overwrite-dbs to overwrite).")
            return True

    # Validate that repository path exists
    if not os.path.exists(repo_path):
        logger.error(f"Repository path does not exist: {repo_path}")
        return False

    if not os.path.isdir(repo_path):
        logger.error(f"Repository path is not a directory: {repo_path}")
        return False

    # Get the path to the build script
    scanner_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # If build_name is provided, look in: scanner/repos_builds_cmds/<alias>/<build_name>/build.sh
    # Otherwise, look in: scanner/repos_builds_cmds/<alias>/build.sh
    if build_name:
        build_script_path = os.path.join(scanner_dir, "scanner", "repos_builds_cmds", alias, build_name, "build.sh")
    else:
        build_script_path = os.path.join(scanner_dir, "scanner", "repos_builds_cmds", alias, "build.sh")

    # Check if build script exists
    if os.path.exists(build_script_path):
        # Build script found - use it
        logger.info(f"Using custom build script: {build_script_path}")

        # Verify it's a file
        if not os.path.isfile(build_script_path):
            logger.error(f"Build script path exists but is not a file: {build_script_path}")
            return False

        command = [
            "codeql", "database", "create", db_path,
            "--language=c-cpp",
            f"--source-root={repo_path}",
            f"--command={build_script_path}"
        ]
        if overwrite:
            command.append("--overwrite")
        logger.info(f"Running command: {' '.join(command)}")
    else:
        # Build script not found
        if build_name:
            # If a specific build_name was requested, the build script MUST exist
            logger.error(f"Build script not found at {build_script_path}")
            logger.error(f"Build name '{build_name}' was explicitly specified but no build script exists")
            logger.error(f"Please create the build script or remove the build name specification")
            return False
        else:
            # No specific build_name, fall back to auto-detection
            logger.warning(f"Build script not found at {build_script_path}")
            logger.warning(f"Running CodeQL without custom build command (auto-detection mode)")
            command = [
                "codeql", "database", "create", db_path,
                "--language=c-cpp",
                f"--source-root={repo_path}"
            ]
            if overwrite:
                command.append("--overwrite")
            logger.info(f"Running command: {' '.join(command)}")

    try:
        logger.info("CodeQL database creation in progress (this may take several minutes)...")

        # Use Popen to stream output in real-time
        process = subprocess.Popen(
            command,
            cwd=repo_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered
            universal_newlines=True
        )

        # Use threading to read both stdout and stderr simultaneously
        import threading
        import queue

        output_queue = queue.Queue()

        def read_stream(stream, stream_name):
            """Read from a stream and put lines in the queue."""
            try:
                for line in iter(stream.readline, ''):
                    if line:
                        output_queue.put((stream_name, line.rstrip()))
            finally:
                stream.close()

        # Start threads to read stdout and stderr
        stdout_thread = threading.Thread(target=read_stream, args=(process.stdout, 'stdout'))
        stderr_thread = threading.Thread(target=read_stream, args=(process.stderr, 'stderr'))
        stdout_thread.daemon = True
        stderr_thread.daemon = True
        stdout_thread.start()
        stderr_thread.start()

        # Read and log output in real-time
        import time
        while process.poll() is None or not output_queue.empty():
            try:
                stream_name, line = output_queue.get(timeout=0.1)
                if line:
                    logger.info(f"  [{stream_name}] {line}")
            except queue.Empty:
                continue

        # Wait for threads to finish
        stdout_thread.join(timeout=1)
        stderr_thread.join(timeout=1)

        # Get the return code
        return_code = process.returncode

        if return_code == 0:
            logger.info(f"Successfully created CodeQL database at: {db_path}")
            return True
        else:
            logger.error(f"Failed to create CodeQL database. Exit code: {return_code}")
            return False

    except Exception as e:
        logger.error(f"Exception during CodeQL database creation: {e}", exc_info=True)
        return False

def _run_and_process_query(db_path: str, repo_path: str, alias: str, build_name: str | None = None) -> list[dict]:
    """
    Run CodeQL query and process results.

    Args:
        db_path: Path to the CodeQL database
        repo_path: Path to the repository
        alias: Repository alias
        build_name: Optional build configuration name

    Returns:
        List of function declarations
    """
    query_file_path = os.path.join((os.path.dirname(os.path.abspath(__file__))), "query", "query.ql")

    # Create repos_analysis directory
    scanner_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    analysis_dir = os.path.join(scanner_dir, "scanner", "repos_analysis")
    os.makedirs(analysis_dir, exist_ok=True)

    # Generate file names based on alias and build_name
    if build_name:
        base_name = f"{alias}-{build_name}"
    else:
        base_name = alias

    bqrs_path = os.path.join(analysis_dir, f"{base_name}.bqrs")
    csv_path = os.path.join(analysis_dir, f"{base_name}.csv")

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
        logger.info(f"Running command: {' '.join(run_command)}")
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
        logger.info(f"Running command: {' '.join(decode_command)}")
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

def parse_repo_headers_with_codeql(repo_path: str, alias: str, build_name: str | None = None, overwrite_dbs: bool = False) -> list[dict]:
    """
    Analyzes a C++ repository using CodeQL to extract public function declarations.

    Args:
        repo_path: The absolute path to the root of the repository.
        alias: The alias for this repository.
        build_name: Optional build configuration name (e.g., 'default', 'no-asm')
        overwrite_dbs: Whether to overwrite existing CodeQL databases

    Returns:
        A list of dictionaries, where each dictionary represents a unique function declaration.
    """
    if not CODEQL_AVAILABLE:
        logger.error("Cannot parse repository because CodeQL CLI is not available or not found in PATH.")
        return []

    repo_path = os.path.abspath(repo_path)
    repo_name = os.path.basename(repo_path)

    # Use scanner/repos_databases folder for database storage
    scanner_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_dir = os.path.join(scanner_dir, "scanner", "repos_databases")
    os.makedirs(db_dir, exist_ok=True)

    # Database name includes build_name if provided: alias-build_name.db
    if build_name:
        db_path = os.path.join(db_dir, f"{alias}-{build_name}.db")
    else:
        db_path = os.path.join(db_dir, f"{alias}.db")

    if not _create_codeql_database(repo_path, db_path, alias, build_name, overwrite_dbs):
        return []

    all_functions = _run_and_process_query(db_path, repo_path, alias, build_name)

    build_suffix = f" with build '{build_name}'" if build_name else ""
    logger.info(f"Finished parsing '{repo_name}' (alias: {alias}{build_suffix}). Extracted {len(all_functions)} unique function declarations.")
    return all_functions

# --- Initialization ---
_initialize_codeql_cli()
