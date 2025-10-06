import os
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

REPOS_DIR = "repos"

def get_repo_name_from_url(repo_url: str) -> str:
    try:
        path = urlparse(repo_url).path.strip('/')
        parts = path.split('/')
        if len(parts) >= 2:
            repo_name = parts[-1]
            if repo_name.endswith(".git"):
                repo_name = repo_name[:-4]
            return repo_name or "unknown_repo"
        else:
            repo_name = path
            if repo_name.endswith(".git"):
                repo_name = repo_name[:-4]
            return repo_name or "unknown_repo"
    except Exception:
        logger.exception(f"Error parsing repo name from URL: {repo_url}")
        return "unknown_repo"

def clone_repo(repo_url: str, base_dir: str = REPOS_DIR) -> tuple[str | None, str]:
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
        env = os.environ.copy()
        env['GIT_TERMINAL_PROMPT'] = '0'

        git_command = ["git", "clone", "--depth=1", "--no-tags", "--single-branch", repo_url, local_path]
        logger.info(f"Running command: {' '.join(git_command)}")

        process = subprocess.run(
            git_command,
            check=True,
            capture_output=True,
            text=True,
            env=env
        )
        logger.info(f"Successfully cloned '{repo_name}'.")
        return local_path, repo_name
    except subprocess.CalledProcessError as e:
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
"""
def batch_clone(repo_urls: list[str], max_workers: int = 5) -> dict[str, str]:
    cloned_repos = {}

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
            except Exception as e:
                logger.error(f"Error processing clone result for {url}: {e}", exc_info=True)

    logger.info(f"Batch clone finished. Successfully cloned {len(cloned_repos)} out of {len(repo_urls)} requested repositories.")
    return cloned_repos
"""
