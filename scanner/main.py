import sys
import argparse
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Use absolute imports within the package when running with -m
from scanner.git_cloner import clone_repo # Use clone_repo directly now
from scanner.parser import parse_repo_headers, LIBCLANG_INITIALIZED
from scanner.utils import get_library_info
from scanner.db_builder import build_database

# Configure basic logging
# Define logger at the module level
logger = logging.getLogger("scanner") # Use root logger for the package
# Configure root logger (best practice)
# Use force=True to potentially override handlers set by other libraries if needed
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(asctime)s %(name)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S', force=True)


def process_repository(repo_url: str, clone_dir: str, parser_workers: int | None) -> dict | None:
    """
    Clones, parses, and gathers info for a single repository.
    Returns a dictionary with results or None if cloning/processing fails.
    """
    # Create a more specific logger for this repo processing task
    repo_short_name = repo_url.split('/')[-1].replace('.git','')
    repo_logger = logging.getLogger(f"scanner.repo.{repo_short_name}")
    repo_logger.info(f"--- Starting processing ---")
    start_time = time.time()

    try:
        # 1. Clone the repository
        local_path, repo_name = clone_repo(repo_url, base_dir=clone_dir)

        if not local_path:
            # Error already logged by clone_repo
            repo_logger.error("Cloning failed.")
            return None

        # 2. Detect Library Name and Version (pass repo_url for API fallback)
        library_name, library_version = get_library_info(local_path, repo_name, repo_url)
        repo_logger.info(f"Detected Library: {library_name} Version: {library_version or 'Unknown'}")


        # 3. Parse Headers (check if libclang is usable first)
        if not LIBCLANG_INITIALIZED:
             repo_logger.error("Skipping header parsing because libclang failed to initialize.")
             functions = [] # Return empty functions list
        else:
            repo_logger.info(f"Parsing headers...")
            functions = parse_repo_headers(local_path, max_workers=parser_workers)

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
        return None # Ensure failure returns None

def main():
    parser = argparse.ArgumentParser(
        description="Scan cryptographic library repositories for function signatures.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # Show defaults in help
    )
    parser.add_argument("repo_urls", nargs='+', help="One or more GitHub repository URLs to scan.")
    parser.add_argument("--clone-dir", default="repos", help="Directory to clone repositories into.")
    parser.add_argument("--output-dir", default="output", help="Directory to save JSON database files.")
    # Renamed clone-workers to repo-workers for clarity as it controls repo processing concurrency
    parser.add_argument("--repo-workers", type=int, default=5, help="Number of parallel workers for processing repositories.")
    parser.add_argument("--parser-workers", type=int, default=os.cpu_count(), help="Number of parallel workers for parsing headers *per* repo.")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set logging level.")

    args = parser.parse_args()

    # Set logging level for the root logger of the 'scanner' package
    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    # Get the package root logger and set its level
    package_logger = logging.getLogger("scanner")
    package_logger.setLevel(log_level)
    # Ensure handlers are configured if basicConfig wasn't called or needs override
    # Use force=True to potentially override handlers set by other libraries if needed
    # Check if handlers already exist to avoid duplicates if run multiple times in same process
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
    logger.info(f"Clone directory: {os.path.abspath(args.clone_dir)}")
    logger.info(f"Output directory: {os.path.abspath(args.output_dir)}")
    logger.info(f"Max repo processing workers: {args.repo_workers}")
    logger.info(f"Max parser workers per repo: {args.parser_workers}")
    logger.info(f"Log level set to: {args.log_level}")
    logger.info("---------------------------------------")


    # Ensure clone and output directories exist
    try:
        os.makedirs(args.clone_dir, exist_ok=True)
        os.makedirs(args.output_dir, exist_ok=True)
    except OSError as e:
        logger.critical(f"Failed to create necessary directories ({args.clone_dir}, {args.output_dir}): {e}")
        sys.exit(1)


    # Update global output directory variables in db_builder module
    from scanner import db_builder
    db_builder.OUTPUT_DIR = args.output_dir
    db_builder.PRIMITIVES_FILE = os.path.join(args.output_dir, "primitives.json")
    db_builder.LIBRARIES_FILE = os.path.join(args.output_dir, "libraries.json")
    logger.info(f"Database output files: {db_builder.LIBRARIES_FILE}, {db_builder.PRIMITIVES_FILE}")


    overall_start_time = time.time()
    all_results = []

    # Use ThreadPoolExecutor for managing the processing of each repository
    max_repo_workers = min(args.repo_workers, len(args.repo_urls))
    if max_repo_workers <= 0:
         logger.warning("No repositories specified or zero workers requested. Exiting.")
         sys.exit(0)

    logger.info(f"Processing {len(args.repo_urls)} repositories using up to {max_repo_workers} concurrent workers...")

    with ThreadPoolExecutor(max_workers=max_repo_workers, thread_name_prefix="RepoWorker") as executor:
        # Pass repo_url to get_library_info inside process_repository
        future_to_url = {
            executor.submit(process_repository, url, args.clone_dir, args.parser_workers): url
            for url in args.repo_urls
        }

        completed_count = 0
        total_count = len(future_to_url)
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            completed_count += 1
            # Progress indication can be simple or more detailed
            # logger.info(f"Progress: {completed_count}/{total_count} repositories complete.")
            try:
                result = future.result()
                if result:
                    all_results.append(result)
                # else: # Failure logged within process_repository
                    # logger.warning(f"Processing failed or was skipped for repository: {url}")
            except Exception as e:
                # Catch potential exceptions from future.result() itself
                logger.error(f"An error occurred retrieving result for repository {url}: {e}", exc_info=True)

    successful_count = len(all_results)
    failed_count = total_count - successful_count
    logger.info("---------------------------------------")
    logger.info(f"Finished processing all repositories.")
    logger.info(f"  Successfully processed: {successful_count}")
    logger.info(f"  Failed or skipped:    {failed_count}")
    logger.info("---------------------------------------")


    # 4. Build/Update the Database
    if all_results:
        logger.info("Building/Updating database...")
        try:
            build_database(all_results)
            logger.info("Database build complete.")
        except Exception as e:
            logger.critical(f"Failed to build or save the database: {e}", exc_info=True)
            # Decide if this is a fatal error for the script
            # sys.exit(1)
    elif successful_count == 0 and total_count > 0:
         logger.error("No repositories were processed successfully. Database not updated.")
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
