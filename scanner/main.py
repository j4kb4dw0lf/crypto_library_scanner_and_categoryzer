import sys
import argparse
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.git_cloner import clone_repo 
from scanner.external_cloner import clone_external_lib
from scanner.parser import parse_repo_headers_with_codeql, CODEQL_AVAILABLE
from scanner.utils import get_library_info
from scanner.db_builder import build_database_sqlite as build_database

logger = logging.getLogger("scanner")
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(asctime)s %(name)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S', force=True)

def process_repository(repo_url: str, clone_dir: str) -> dict | None:
    repo_short_name = repo_url.split('/')[-1].replace('.git','')
    repo_logger = logging.getLogger(f"scanner.repo.{repo_short_name}")
    repo_logger.info(f"--- Starting processing ---")
    start_time = time.time()

    try:
        local_path, repo_name = clone_repo(repo_url, base_dir=clone_dir)

        if not local_path:
            repo_logger.error("Cloning failed.")
            return None

        library_name, library_version = get_library_info(local_path, repo_name, repo_url)
        repo_logger.info(f"Detected Library: {library_name} Version: {library_version or 'Unknown'}")

        if not CODEQL_AVAILABLE:
             repo_logger.error("Skipping header parsing because libclang failed to initialize.")
             functions = []
        else:
            repo_logger.info(f"Parsing headers...")
            input(f"Press Enter to start parsing headers for {repo_name}...")  # Wait for user input to continue
            functions = parse_repo_headers_with_codeql(local_path)

        end_time = time.time()
        duration = end_time - start_time
        repo_logger.info(f"--- Finished processing in {duration:.2f} seconds. Found {len(functions)} functions. ---")

        return {
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

def process_external_library(external_lib_path: str, external_libs_dir: str) -> dict | None:
    external_lib_short_name = os.path.basename(os.path.normpath(external_lib_path))
    external_lib_logger = logging.getLogger(f"scanner.external_lib.{external_lib_short_name}")
    external_lib_logger.info(f"--- Starting processing ---")
    start_time = time.time()

    try:
        local_path, external_lib_name = clone_external_lib(external_lib_path, base_dir=external_libs_dir)

        if not local_path:
            external_lib_logger.error("Cloning failed.")
            return None

        external_lib_logger.info("Please provide the library name and version for the external library.")
        library_name = input(f"Enter library name for {external_lib_short_name} (or press Enter to use {external_lib_short_name}): ").strip()
        library_version = input(f"Enter library version for {external_lib_short_name} (or press Enter to skip): ").strip()

        if not library_name:
            library_name = external_lib_short_name

        if not library_version:
            library_version = "Unknown"

        external_lib_logger.info(f"Detected Library: {library_name} Version: {library_version}")

        if not CODEQL_AVAILABLE:
             external_lib_logger.error("Skipping header parsing because libclang failed to initialize.")
             functions = []
        else:
            external_lib_logger.info(f"Parsing headers...")
            functions = parse_repo_headers_with_codeql(local_path)

        end_time = time.time()
        duration = end_time - start_time
        external_lib_logger.info(f"--- Finished processing in {duration:.2f} seconds. Found {len(functions)} functions. ---")

        return {
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
    parser.add_argument("-ru", "--repo-urls", nargs='+', help="One or more GitHub repository URLs to scan.")
    parser.add_argument("-elp", "--external-libs-paths", nargs='+', help="One or more external libraries to scan.")
    parser.add_argument("--clone-dir", default="repos", help="Directory to clone repositories into.")
    parser.add_argument("--external-libs-dir", default="external_libs", help="Directory to move external libraries into.")
    parser.add_argument("--output-dir", default="output", help="Directory to save JSON database files.")
    parser.add_argument("--repo-workers", type=int, default=5, help="Number of parallel workers for processing repositories.")
    parser.add_argument("--parser-workers", type=int, default=os.cpu_count(), help="Number of parallel workers for parsing headers *per* repo.")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set logging level.")

    args = parser.parse_args()

    if not args.repo_urls and not args.external_libs_paths:
        print("[ERROR] You must provide at least one of --repo-urls or --external-libs-paths.")
        sys.exit(0)

    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    package_logger = logging.getLogger("scanner")
    package_logger.setLevel(log_level)
    root_logger = logging.getLogger()
    if not root_logger.hasHandlers():
         logging.basicConfig(level=log_level, format='[%(levelname)s] %(asctime)s %(name)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    else:
         root_logger.setLevel(log_level)
         for handler in root_logger.handlers:
              handler.setLevel(log_level)

    logger.info("=======================================")
    logger.info("       Starting Crypto Scanner")
    logger.info("=======================================")
    logger.info(f"Repositories to scan: {len(args.repo_urls)}")
    logger.info(f"External libraries to scan: {len(args.external_libs_paths)}")
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
    max_repo_workers = min(args.repo_workers, len(args.repo_urls))
    if max_repo_workers <= 0:
         logger.warning("No repositories specified or zero workers requested. Exiting.")
         sys.exit(0)

    logger.info(f"Processing {len(args.repo_urls)} repositories using up to {max_repo_workers} concurrent workers...")
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
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="RepoWorker") as executor:
        future_to_url = {
            executor.submit(process_repository, url, args.clone_dir): url
            for url in args.repo_urls
        }

        repo_count = len(future_to_url)
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                if result:
                    repo_results.append(result)
            except Exception as e:
                logger.error(f"An error occurred retrieving result for repository {url}: {e}", exc_info=True)

    successful_count = len(repo_results)
    failed_count = repo_count - successful_count
    logger.info("---------------------------------------")
    logger.info(f"Finished processing all repositories.")
    logger.info(f"  Successfully processed: {successful_count}")
    logger.info(f"  Failed or skipped:    {failed_count}")
    logger.info("---------------------------------------")

    external_results = []
    max_repo_workers = min(args.repo_workers, len(args.external_libs_paths))
    if max_repo_workers <= 0:
         logger.warning("No repositories specified or zero workers requested. Exiting.")
         sys.exit(0)

    logger.info(f"Processing {len(args.external_libs_paths)} external libraries using up to {max_repo_workers} concurrent workers...")

    with ThreadPoolExecutor(max_workers=max_repo_workers, thread_name_prefix="RepoWorker") as executor:
        future_to_url = {
            executor.submit(process_external_library, url, args.external_libs_dir): url
            for url in args.external_libs_paths
        }

        external_count = len(future_to_url)
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                if result:
                    external_results.append(result)
            except Exception as e:
                logger.error(f"An error occurred retrieving result for repository {url}: {e}", exc_info=True)

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
