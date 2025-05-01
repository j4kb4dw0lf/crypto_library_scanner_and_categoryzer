import os
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# Configure basic logging
# Use getLogger for package-aware logging
logger = logging.getLogger(__name__)

REPOS_DIR = "repos" # Relative path within the project

def get_repo_name_from_url(repo_url: str) -> str:
    """Extracts a likely repository name from its URL."""
    try:
        path = urlparse(repo_url).path.strip('/') # Strip leading/trailing slashes
        parts = path.split('/')
        if len(parts) >= 2:
             repo_name = parts[-1]
             if repo_name.endswith(".git"):
                 repo_name = repo_name[:-4]
             return repo_name or "unknown_repo"
        else:
             # Handle cases like just 'repo.git' or invalid paths
             repo_name = path
             if repo_name.endswith(".git"):
                  repo_name = repo_name[:-4]
             return repo_name or "unknown_repo"

    except Exception:
        logger.exception(f"Error parsing repo name from URL: {repo_url}")
        return "unknown_repo"

def clone_repo(repo_url: str, base_dir: str = REPOS_DIR) -> tuple[str | None, str]:
    """
    Clones a single GitHub repo into the specified base directory.
    Uses a shallow clone (--depth=1) for speed. Skips if already cloned.
    Returns a tuple: (local_path_or_None, repo_name).
    """
    repo_name = get_repo_name_from_url(repo_url)
    local_path = os.path.join(base_dir, repo_name)

    if os.path.exists(local_path) and os.path.isdir(os.path.join(local_path, '.git')):
        logger.info(f"Repo '{repo_name}' already exists at '{local_path}'. Skipping clone.")
        return local_path, repo_name
    elif os.path.exists(local_path):
         logger.warning(f"Path '{local_path}' exists but doesn't seem to be a git repo. Attempting to remove and clone.")
         try:
             import shutil
             shutil.rmtree(local_path)
         except OSError as e:
              logger.error(f"Failed to remove existing directory '{local_path}': {e}. Skipping clone.")
              return None, repo_name


    os.makedirs(base_dir, exist_ok=True)

    logger.info(f"Cloning '{repo_url}' into '{local_path}'...")
    try:
        # Set GIT_TERMINAL_PROMPT=0 environment variable for the subprocess
        env = os.environ.copy()
        env['GIT_TERMINAL_PROMPT'] = '0'

        # Use --depth=1 for a shallow clone (faster, less disk space)
        # Capture output for better error diagnosis
        process = subprocess.run(
            ["git", "clone", "--depth=1", "--no-tags", "--single-branch", repo_url, local_path],
            check=True,
            capture_output=True, # Captures stdout and stderr
            text=True, # Decodes stdout/stderr as text
            env=env # Pass modified environment
        )
        logger.info(f"Successfully cloned '{repo_name}'.")
        return local_path, repo_name
    except subprocess.CalledProcessError as e:
        # Provide more context in the error log
        logger.error(f"Failed to clone {repo_url}. Git command failed with exit code {e.returncode}.")
        logger.error(f"Git stderr: {e.stderr.strip()}")
        logger.error(f"Git stdout: {e.stdout.strip()}")
        return None, repo_name
    except FileNotFoundError:
        logger.error("Git command not found. Ensure git is installed and in the system PATH.")
        return None, repo_name
    except Exception as e:
        logger.error(f"An unexpected error occurred during cloning of {repo_url}: {e}", exc_info=True)
        return None, repo_name


# Note: batch_clone remains the same, it just calls the updated clone_repo
def batch_clone(repo_urls: list[str], max_workers: int = 5) -> dict[str, str]:
    """
    Batch clone multiple repos concurrently using a ThreadPoolExecutor.
    Returns a dictionary mapping repo name to its local path. Skips failed clones.
    """
    cloned_repos = {} # Store {repo_name: local_path}

    actual_workers = min(max_workers, len(repo_urls))
    if actual_workers <= 0:
        return {}

    logger.info(f"Starting batch clone for {len(repo_urls)} repositories using up to {actual_workers} workers...")

    with ThreadPoolExecutor(max_workers=actual_workers) as executor:
        future_to_url = {executor.submit(clone_repo, url): url for url in repo_urls}

        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                local_path, repo_name = future.result()
                if local_path:
                    cloned_repos[repo_name] = local_path
                # else: # Error logged within clone_repo
                    # logger.warning(f"Cloning failed or was skipped for {url} (Repo Name: {repo_name}).")
            except Exception as e:
                logger.error(f"Error processing clone result for {url}: {e}", exc_info=True)

    logger.info(f"Batch clone finished. Successfully cloned {len(cloned_repos)} out of {len(repo_urls)} requested repositories.")
    return cloned_repos

# Example usage (optional, for testing)
if __name__ == '__main__':
    # Setup logger for standalone testing
    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(asctime)s %(name)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    test_urls = [
        "https://github.com/openssl/openssl.git",
        "https://github.com/libssh/libssh.git", # This might still fail if there's a persistent issue
        "https://github.com/weidai11/cryptopp.git",
        "https://github.com/nonexistent/repo-should-fail.git" # Example of a failing repo
    ]
    results = batch_clone(test_urls, max_workers=4)
    print("\nCloned Repositories:")
    for name, path in results.items():
        print(f"- {name}: {path}")
