import sys
import argparse
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from scanner.git_cloner import clone_repo
from scanner.external_cloner import clone_external_lib
from scanner.parser import parse_repo_headers_with_codeql, CODEQL_AVAILABLE
from scanner.utils import get_library_info
from scanner.db_builder import build_database_sqlite as build_database

# ANSI color codes
class ColoredFormatter(logging.Formatter):
    """Custom formatter to add colors to entire log messages."""

    # ANSI escape codes for colors
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[37m',       # White
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[91m',      # Bright Red
        'CRITICAL': '\033[1;91m', # Bold Bright Red
    }
    RESET = '\033[0m'

    def format(self, record):
        # Check if this is a command log (starts with "Running command:")
        is_command = hasattr(record, 'msg') and isinstance(record.msg, str) and record.msg.startswith("Running command:")

        # Format the message first
        result = super().format(record)

        # Replace [INFO] with [INFO-CMD] for command logs
        if is_command and record.levelname == 'INFO':
            result = result.replace('[INFO]', '[INFO-CMD]', 1)

        # Add color to the entire line based on log level
        if record.levelname in self.COLORS:
            result = f"{self.COLORS[record.levelname]}{result}{self.RESET}"
        return result

# Configure logging with colored formatter
logger = logging.getLogger("scanner")
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter('[%(levelname)s] %(asctime)s %(name)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)
logging.root.handlers = []  # Remove any default handlers

def _is_valid_url(url: str) -> bool:
    """Check if a string is a valid URL."""
    try:
        result = urlparse(url)
        # Check if scheme and netloc are present (http://, https://, git://, etc.)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def validate_args(args):
    """
    Validate command-line arguments.

    Checks:
    1. repo-urls and external-libs-paths have the correct syntax: <alias>:<path>
    2. No duplicate aliases across both online and offline sources
    3. build-name aliases reference existing aliases from repo-urls or external-libs-paths
    4. repo-urls contain valid URLs
    5. build-name can specify multiple comma-separated build configurations per alias
    """
    errors = []

    # Parse repo-urls
    repo_aliases = {}
    if args.repo_urls:
        for entry in args.repo_urls:
            if ':' not in entry:
                errors.append(f"Invalid syntax for --repo-urls entry '{entry}'. Expected format: <alias>:<url>")
                continue

            parts = entry.split(':', 1)
            if len(parts) != 2:
                errors.append(f"Invalid syntax for --repo-urls entry '{entry}'. Expected format: <alias>:<url>")
                continue

            alias, url = parts
            if not alias or not url:
                errors.append(f"Invalid syntax for --repo-urls entry '{entry}'. Both alias and URL must be non-empty.")
                continue

            # Validate URL format
            if not _is_valid_url(url):
                errors.append(f"Invalid URL in --repo-urls entry '{entry}'. The URL '{url}' is not a valid URL.")
                continue

            if alias in repo_aliases:
                errors.append(f"Duplicate alias '{alias}' found in --repo-urls.")
            else:
                repo_aliases[alias] = url

    # Parse external-libs-paths
    external_aliases = {}
    if args.external_libs_paths:
        for entry in args.external_libs_paths:
            if ':' not in entry:
                errors.append(f"Invalid syntax for --external-libs-paths entry '{entry}'. Expected format: <alias>:<path>")
                continue

            parts = entry.split(':', 1)
            if len(parts) != 2:
                errors.append(f"Invalid syntax for --external-libs-paths entry '{entry}'. Expected format: <alias>:<path>")
                continue

            alias, path = parts
            if not alias or not path:
                errors.append(f"Invalid syntax for --external-libs-paths entry '{entry}'. Both alias and path must be non-empty.")
                continue

            if alias in external_aliases:
                errors.append(f"Duplicate alias '{alias}' found in --external-libs-paths.")
            else:
                external_aliases[alias] = path

    # Check for duplicate aliases across repo_urls and external_libs_paths
    for alias in external_aliases:
        if alias in repo_aliases:
            errors.append(f"Duplicate alias '{alias}' found across --repo-urls and --external-libs-paths.")

    # Combine all aliases
    all_aliases = set(repo_aliases.keys()) | set(external_aliases.keys())

    # Parse and validate build-name (now supports multiple build names per alias)
    # Format: <alias>:<build_name1>,<build_name2>,... or just <alias> for default build
    build_names_map = {}
    if args.build_name:
        for entry in args.build_name:
            if ':' not in entry:
                errors.append(f"Invalid syntax for --build-name entry '{entry}'. Expected format: <alias>:<build_name1>,<build_name2> or <alias>:default")
                continue

            parts = entry.split(':', 1)
            if len(parts) != 2:
                errors.append(f"Invalid syntax for --build-name entry '{entry}'. Expected format: <alias>:<build_name1>,<build_name2>")
                continue

            alias, build_names_str = parts
            if not alias or not build_names_str:
                errors.append(f"Invalid syntax for --build-name entry '{entry}'. Both alias and build names must be non-empty.")
                continue

            if alias not in all_aliases:
                errors.append(f"Alias '{alias}' in --build-name does not match any alias in --repo-urls or --external-libs-paths.")
                continue

            # Split by comma to support multiple build names
            build_names = [name.strip() for name in build_names_str.split(',') if name.strip()]
            if not build_names:
                errors.append(f"No valid build names provided for alias '{alias}' in --build-name entry '{entry}'.")
                continue

            # Store as a list of build names per alias
            if alias in build_names_map:
                errors.append(f"Duplicate alias '{alias}' found in --build-name entries.")
            else:
                build_names_map[alias] = build_names

    # Report errors
    if errors:
        for error in errors:
            print(f"[ERROR] {error}")
        sys.exit(1)

    return repo_aliases, external_aliases, build_names_map

def process_repository(alias: str, repo_url: str, clone_dir: str, build_name: str | None = None, overwrite_dbs: bool = False) -> dict | None:
    """
    Process a repository with optional build configuration.

    Args:
        alias: Repository alias
        repo_url: Repository URL
        clone_dir: Directory to clone into
        build_name: Optional build configuration name (e.g., 'default', 'no-asm', etc.)
        overwrite_dbs: Whether to overwrite existing CodeQL databases
    """
    build_suffix = f"-{build_name}" if build_name else ""
    repo_logger = logging.getLogger(f"scanner.repo.{alias}{build_suffix}")
    repo_logger.info(f"--- Starting processing (alias: {alias}{build_suffix}) ---")
    start_time = time.time()

    try:
        local_path, repo_name = clone_repo(repo_url, base_dir=clone_dir)

        if not local_path:
            repo_logger.error("Cloning failed.")
            return None

        library_name, library_version = get_library_info(local_path, repo_name, repo_url)
        repo_logger.info(f"Detected Library: {library_name} Version: {library_version or 'Unknown'}")
        if build_name:
            repo_logger.info(f"Build configuration: {build_name}")

        if not CODEQL_AVAILABLE:
             repo_logger.error("Skipping header parsing because codeql failed to initialize.")
             functions = []
        else:
            repo_logger.info(f"Parsing headers...")
            input(f"Press Enter to start parsing headers for {repo_name}{build_suffix}...")  # Wait for user input to continue
            functions = parse_repo_headers_with_codeql(local_path, alias, build_name, overwrite_dbs)

        end_time = time.time()
        duration = end_time - start_time
        repo_logger.info(f"--- Finished processing in {duration:.2f} seconds. Found {len(functions)} functions. ---")

        return {
            'alias': alias,
            'build_name': build_name,
            'repo_name': repo_name,
            'library_name': library_name,
            'library_version': library_version,
            'repo_url': repo_url,
            'local_path': local_path,
            'functions': functions
        }
    except Exception as e:
        repo_logger.error(f"Unhandled exception during processing: {e}", exc_info=True)
        return None

def process_external_library(alias: str, external_lib_path: str, external_libs_dir: str) -> dict | None:
    external_lib_logger = logging.getLogger(f"scanner.external_lib.{alias}")
    external_lib_logger.info(f"--- Starting processing (alias: {alias}) ---")
    start_time = time.time()

    try:
        local_path, external_lib_name = clone_external_lib(external_lib_path, base_dir=external_libs_dir)

        if not local_path:
            external_lib_logger.error("Cloning failed.")
            return None

        external_lib_logger.info("Please provide the library name and version for the external library.")
        library_name = input(f"Enter library name for {alias} (or press Enter to use {alias}): ").strip()
        library_version = input(f"Enter library version for {alias} (or press Enter to skip): ").strip()

        if not library_name:
            library_name = alias

        if not library_version:
            library_version = "Unknown"

        external_lib_logger.info(f"Detected Library: {library_name} Version: {library_version}")

        if not CODEQL_AVAILABLE:
             external_lib_logger.error("Skipping header parsing because codeql failed to initialize.")
             functions = []
        else:
            external_lib_logger.info(f"Parsing headers...")
            functions = parse_repo_headers_with_codeql(local_path, alias)

        end_time = time.time()
        duration = end_time - start_time
        external_lib_logger.info(f"--- Finished processing in {duration:.2f} seconds. Found {len(functions)} functions. ---")

        return {
            'alias': alias,
            'external_lib_name': external_lib_name,
            'library_name': library_name,
            'library_version': library_version,
            'external_lib_path': external_lib_path,
            'local_path': local_path,
            'functions': functions
        }
    except Exception as e:
        external_lib_logger.error(f"Unhandled exception during processing: {e}", exc_info=True)
        return None

def main():
    parser = argparse.ArgumentParser(
        description="Scan cryptographic library repositories for function signatures.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-ru", "--repo-urls", nargs='+', help="One or more GitHub repository URLs to scan. Format: <alias>:<url>")
    parser.add_argument("-elp", "--external-libs-paths", nargs='+', help="One or more external libraries to scan. Format: <alias>:<path>")
    parser.add_argument("-bn", "--build-name", nargs='+', help="Build configurations for specific aliases. Format: <alias>:<build_name1>,<build_name2>. Can specify multiple builds per alias.")
    parser.add_argument("--clone-dir", default="repos", help="Directory to clone repositories into.")
    parser.add_argument("--external-libs-dir", default="external_libs", help="Directory to move external libraries into.")
    parser.add_argument("--output-dir", default="output", help="Directory to save JSON database files.")
    parser.add_argument("--repo-workers", type=int, default=5, help="Number of parallel workers for processing repositories.")
    parser.add_argument("--parser-workers", type=int, default=os.cpu_count(), help="Number of parallel workers for parsing headers *per* repo.")
    parser.add_argument("--overwrite-dbs", action="store_true", help="Overwrite existing CodeQL databases if they already exist.")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set logging level.")

    args = parser.parse_args()

    if not args.repo_urls and not args.external_libs_paths:
        print("[ERROR] You must provide at least one of --repo-urls (-ru) or --external-libs-paths (-elp).")
        print("\nUsage patterns:")
        print("  -ru/--repo-urls:")
        print("    Format: <alias>:<git_url>")
        print("    Example: -ru openssl:https://github.com/openssl/openssl.git libsodium:https://github.com/jedisct1/libsodium.git")
        print("    Description: Specifies Git repositories to clone and scan")
        print("")
        print("  -elp/--external-libs-paths:")
        print("    Format: <alias>:<local_path>")
        print("    Example: -elp mylib:/path/to/local/library")
        print("    Description: Specifies local directories containing source code to scan")
        print("")
        print("  -bn/--build-name (optional):")
        print("    Format: <alias>:<build_name1>,<build_name2>,... [<alias2>:<build_name>]")
        print("    Example 1: -bn openssl:buildA,buildB")
        print("               (scans openssl with two type of builds: 'buildA' and 'buildB')")
        print("    Example 2: -bn openssl:generic libsodium:minimal")
        print("               (scans openssl with 'generic' build, libsodium with 'minimal' build)")
        print("    Description: Specifies custom build configurations for aliases")
        print("    Build script location: scanner/repos_builds_cmds/<alias>/<build_name>/build.sh")
        print("    If omitted, CodeQL will try to auto-detect how to build it")
        print("")
        sys.exit(1)

    # Validate arguments and parse aliases
    repo_aliases, external_aliases, build_names_map = validate_args(args)

    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    package_logger = logging.getLogger("scanner")
    package_logger.setLevel(log_level)

    # Update all handlers with colored formatter
    for handler in package_logger.handlers:
        handler.setLevel(log_level)
        if not isinstance(handler.formatter, ColoredFormatter):
            handler.setFormatter(ColoredFormatter('[%(levelname)s] %(asctime)s %(name)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))

    # Configure root logger with colored formatter
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    if not root_logger.handlers:
        root_handler = logging.StreamHandler()
        root_handler.setFormatter(ColoredFormatter('[%(levelname)s] %(asctime)s %(name)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
        root_logger.addHandler(root_handler)
    else:
        for handler in root_logger.handlers:
            handler.setLevel(log_level)
            if not isinstance(handler.formatter, ColoredFormatter):
                handler.setFormatter(ColoredFormatter('[%(levelname)s] %(asctime)s %(name)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))

    logger.info("=======================================")
    logger.info("       Starting Crypto Scanner")
    logger.info("=======================================")
    logger.info(f"Repositories to scan: {len(repo_aliases)}")
    logger.info(f"External libraries to scan: {len(external_aliases)}")
    logger.info(f"Build configurations specified: {len(build_names_map)}")
    logger.info(f"Clone directory: {os.path.abspath(args.clone_dir)}")
    logger.info(f"external libs directory: {os.path.abspath(args.external_libs_dir)}")
    logger.info(f"Output directory: {os.path.abspath(args.output_dir)}")
    logger.info(f"Max repo processing workers: {args.repo_workers}")
    logger.info(f"Max parser workers per repo: {args.parser_workers}")
    logger.info(f"Log level set to: {args.log_level}")
    logger.info("---------------------------------------")

    try:
        os.makedirs(args.clone_dir, exist_ok=True)
        os.makedirs(args.external_libs_dir, exist_ok=True)
        os.makedirs(args.output_dir, exist_ok=True)
    except OSError as e:
        logger.critical(f"Failed to create necessary directories ({args.clone_dir}, {args.output_dir}): {e}")
        sys.exit(1)

    overall_start_time = time.time()
    all_results = []

    repo_results = []
    repo_count = 0

    if repo_aliases:
        # Create list of (alias, url, build_name) tuples for processing
        # Each alias can have multiple build configurations
        repo_jobs = []
        for alias, url in repo_aliases.items():
            build_names = build_names_map.get(alias, [None])  # None means no specific build
            for build_name in build_names:
                repo_jobs.append((alias, url, build_name))

        repo_count = len(repo_jobs)
        max_repo_workers = min(args.repo_workers, repo_count)

        logger.info(f"Processing {len(repo_aliases)} repositories with {repo_count} total configurations using up to {max_repo_workers} concurrent workers...")

        # Write CodeQL query file
        with open(os.path.join(os.path.dirname((os.path.abspath(__file__))), "query", "query.ql"), 'w') as f:
            query_content = f.write(f"""
/**
 * @name Find Public Function Declarations
 * @description Finds function declarations, their parameters, and locations.
 * @kind table
 * @id cpp/custom/find-function-declarations
 */
import cpp

from Function f
where
    f.getLocation().getFile().getAbsolutePath().matches("%{os.path.dirname(os.path.dirname(os.path.abspath(__file__)))}%")
select
    f.getNamespace().getQualifiedName() as namespace,
    f.getName() as functionName,
    f.getType().toString() as returnType,
    f.getParameterString() as parameterString,
    f.getLocation().getFile().getAbsolutePath() as filePath,
    f.getLocation().getStartLine() as startLine
order by
    filePath, startLine"""
        )
            if not query_content:
                logger.error("Query file is empty or not found. Ensure the query is available.")
                sys.exit(1)

        # Process repositories with their build configurations
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="RepoWorker") as executor:
            future_to_job = {
                executor.submit(process_repository, alias, url, args.clone_dir, build_name, args.overwrite_dbs): (alias, build_name)
                for alias, url, build_name in repo_jobs
            }

            for future in as_completed(future_to_job):
                alias, build_name = future_to_job[future]
                job_name = f"{alias}-{build_name}" if build_name else alias
                try:
                    result = future.result()
                    if result:
                        repo_results.append(result)
                except Exception as e:
                    logger.error(f"An error occurred retrieving result for {job_name}: {e}", exc_info=True)

    if repo_aliases:
        successful_count = len(repo_results)
        failed_count = repo_count - successful_count
        logger.info("---------------------------------------")
        logger.info(f"Finished processing all repositories.")
        logger.info(f"  Successfully processed: {successful_count}")
        logger.info(f"  Failed or skipped:    {failed_count}")
        logger.info("---------------------------------------")

    external_results = []
    external_count = 0

    if external_aliases:
        max_repo_workers = min(args.repo_workers, len(external_aliases))
        external_count = len(external_aliases)

        logger.info(f"Processing {len(external_aliases)} external libraries using up to {max_repo_workers} concurrent workers...")

        with ThreadPoolExecutor(max_workers=max_repo_workers, thread_name_prefix="RepoWorker") as executor:
            future_to_alias = {
                executor.submit(process_external_library, alias, path, args.external_libs_dir): alias
                for alias, path in external_aliases.items()
            }

            for future in as_completed(future_to_alias):
                alias = future_to_alias[future]
                try:
                    result = future.result()
                    if result:
                        external_results.append(result)
                except Exception as e:
                    logger.error(f"An error occurred retrieving result for external library {alias}: {e}", exc_info=True)

    if external_aliases:
        successful_count = len(external_results)
        failed_count = external_count - successful_count
        logger.info("---------------------------------------")
        logger.info(f"Finished processing all external libraries.")
        logger.info(f"  Successfully processed: {successful_count}")
        logger.info(f"  Failed or skipped:    {failed_count}")
        logger.info("---------------------------------------")

    all_results = repo_results + external_results
    total_count = repo_count + external_count
    successful_count = len(all_results)
    failed_count = total_count - successful_count

    if all_results:
        logger.info("Building/Updating database...")
        try:
            build_database(repo_results, external_results)
            logger.info("Database build complete.")
        except Exception as e:
            logger.critical(f"Failed to build or save the database: {e}", exc_info=True)
    elif successful_count == 0 and total_count > 0:
         logger.error("No repositories or external librareis were processed successfully. Database not updated.")
    else:
        logger.warning("No successful repository results to build database from.")

    overall_end_time = time.time()
    total_duration = overall_end_time - overall_start_time
    logger.info("=======================================")
    logger.info(f" Crypto Scanner finished in {total_duration:.2f} seconds.")
    if successful_count > 0:
        logger.info(f" Database files updated in '{os.path.abspath(args.output_dir)}'.")
    logger.info("=======================================")

if __name__ == "__main__":
    main()
