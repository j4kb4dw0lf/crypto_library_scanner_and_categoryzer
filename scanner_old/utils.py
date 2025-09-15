import os
import re
import logging
import requests
from functools import lru_cache
from urllib.parse import urlparse
from packaging import version as packaging_version
import time

logger = logging.getLogger(__name__)

def _extract_owner_repo(repo_url: str) -> tuple[str | None, str | None]:
    if not repo_url:
        return None, None
    try:
        parsed = urlparse(repo_url)
        if parsed.netloc != 'github.com':
            logger.debug(f"URL is not a github.com URL: {repo_url}")
            return None, None

        path_parts = parsed.path.strip('/').split('/')
        if len(path_parts) >= 2:
            owner = path_parts[0]
            repo = path_parts[1]
            if repo.endswith(".git"):
                repo = repo[:-4]
            return owner, repo
        else:
            logger.debug(f"Could not parse owner/repo from path: {parsed.path}")
            return None, None
    except Exception as e:
        logger.warning(f"Error parsing owner/repo from URL {repo_url}: {e}")
        return None, None

def fetch_latest_github_tag(owner: str, repo: str) -> str | None:
    if not owner or not repo:
        return None

    api_url = f"https://api.github.com/repos/{owner}/{repo}/tags"
    logger.debug(f"Fetching tags from GitHub API: {api_url}")

    try:
        headers = {'User-Agent': 'Crypto-Scanner-Bot'}
        response = requests.get(api_url, headers=headers, timeout=15)

        if response.status_code == 403 and 'rate limit exceeded' in response.text.lower():
            logger.warning(f"GitHub API rate limit exceeded for {owner}/{repo}. Cannot fetch version tag.")
            reset_time = response.headers.get('X-RateLimit-Reset')
            if reset_time:
                 try:
                      wait_seconds = int(reset_time) - time.time()
                      if wait_seconds > 0: logger.warning(f"Rate limit resets in approximately {int(wait_seconds / 60)} minutes.")
                 except Exception: pass
            return None
        elif response.status_code == 404:
             logger.warning(f"Repository {owner}/{repo} not found via GitHub API (404).")
             return None

        if response.status_code != 200:
             logger.warning(f"GitHub API request for {owner}/{repo} tags failed with status {response.status_code}: {response.text[:200]}")

        response.raise_for_status()

        tags_data = response.json()
        if not isinstance(tags_data, list):
             logger.warning(f"Unexpected API response format for tags: {tags_data}")
             return None

        valid_versions = []
        for tag_info in tags_data:
            tag_name = tag_info.get('name')
            if not tag_name: continue

            version_part = None
            match_std = re.match(r'^[vV]?(\d+(\.\d+)+.*)', tag_name)
            match_lib = re.match(r'^[a-zA-Z_-]+_(\d+_\d+_\d+)$', tag_name)
            match_lib_dash = re.match(r'^[a-zA-Z_-]+-([\d]+(\.\d+)+.*)', tag_name)

            if match_std:
                version_part = match_std.group(1)
            elif match_lib:
                version_part = match_lib.group(1).replace('_', '.')
            elif match_lib_dash:
                 version_part = match_lib_dash.group(1)
            else:
                logger.debug(f"Tag '{tag_name}' doesn't match known version patterns.")
                continue

            try:
                parsed_ver = packaging_version.parse(version_part)
                valid_versions.append(parsed_ver)
            except packaging_version.InvalidVersion:
                logger.debug(f"Could not parse tag '{tag_name}' (part: '{version_part}') as a valid version.")
                continue

        if not valid_versions:
            logger.info(f"No valid version tags found via GitHub API for {owner}/{repo}.")
            return None

        valid_versions.sort(reverse=True)

        latest_stable = next((v for v in valid_versions if not v.is_prerelease), None)
        if latest_stable:
             latest_version = str(latest_stable)
             logger.info(f"Latest stable version tag found via GitHub API for {owner}/{repo}: {latest_version}")
        else:
             latest_version = str(valid_versions[0])
             logger.info(f"Latest version tag (pre-release) found via GitHub API for {owner}/{repo}: {latest_version}")

        return latest_version

    except requests.exceptions.RequestException as e:
        logger.error(f"Network error fetching tags from GitHub API for {owner}/{repo}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error processing GitHub tags for {owner}/{repo}: {e}", exc_info=True)
        return None

@lru_cache(maxsize=128)
def read_file_content(filepath: str) -> str | None:
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except FileNotFoundError:
        return None
    except (IOError, OSError) as e:
        logger.warning(f"Could not read file {filepath}: {e}")
        return None
    except Exception as e:
         logger.warning(f"Unexpected error reading file {filepath}: {e}")
         return None

def find_first_file(base_dir: str, filenames: list[str]) -> str | None:
    for filename in filenames:
        filepath = os.path.join(base_dir, filename)
        if os.path.isfile(filepath):
            return filepath
    return None

def extract_from_cmake(content: str) -> tuple[str | None, str | None]:
    name = None
    version = None
    match = re.search(r'project\s*\(\s*(\w+)\s*(?:VERSION\s+)?([\w\d\.\-]+)', content, re.IGNORECASE)
    if match:
        name = match.group(1)
        version_str = match.group(2)
        if re.match(r'^[\d\.]', version_str):
             version = version_str
             logger.debug(f"Extracted from CMake: name='{name}', version='{version}'")
    return name, version

def extract_from_configure_ac(content: str) -> tuple[str | None, str | None]:
    name = None
    version = None
    match = re.search(r'AC_INIT\s*\(\s*\[([^\]]+)\]\s*,\s*\[([^\]]+)\]', content)
    if match:
        name = match.group(1).strip()
        version_str = match.group(2).strip()
        if re.match(r'^[\d\.]', version_str):
             version = version_str
             logger.debug(f"Extracted from configure.ac: name='{name}', version='{version}'")
    return name, version

def extract_from_version_file(content: str) -> str | None:
    lines = content.strip().splitlines()
    if lines:
        version_str = lines[0].strip().lstrip('vV')
        if re.match(r'^[\d\.]+[a-zA-Z0-9._-]*$', version_str):
            logger.debug(f"Extracted from VERSION file: version='{version_str}'")
            return version_str
    return None

def get_library_info(repo_path: str, repo_name: str, repo_url: str | None = None) -> tuple[str, str | None]:
    detected_name = repo_name
    detected_version = None

    logger.debug(f"Checking local files for version info in {repo_path}")
    check_files = [
        ("CMakeLists.txt", extract_from_cmake),
        ("configure.ac", extract_from_configure_ac),
        ("VERSION", extract_from_version_file),
        ("version.txt", extract_from_version_file),
        (".version", extract_from_version_file),
    ]

    found_name_local = None
    found_version_local = None

    for filename, extractor in check_files:
        filepath = os.path.join(repo_path, filename)
        if os.path.exists(filepath):
            content = read_file_content(filepath)
            if content:
                if extractor == extract_from_version_file:
                    version = extractor(content)
                    if version and not found_version_local:
                        found_version_local = version
                else:
                    name, version = extractor(content)
                    if name and not found_name_local:
                         found_name_local = name
                    if version and not found_version_local:
                        found_version_local = version

    if found_name_local: detected_name = found_name_local
    detected_version = found_version_local

    logger.info(f"Local file check result: Name='{detected_name}', Version='{detected_version or 'Not Found'}'")

    if not detected_version and repo_url:
        logger.info(f"Version not found locally. Attempting GitHub API fallback for {repo_url}")
        owner, repo = _extract_owner_repo(repo_url)
        if owner and repo:
            api_version = fetch_latest_github_tag(owner, repo)
            if api_version:
                detected_version = api_version
        else:
            logger.warning(f"Could not extract owner/repo from URL '{repo_url}' for API lookup.")

    logger.info(f"Final library info: Name='{detected_name}', Version='{detected_version or 'Not Found'}'")
    return detected_name, detected_version
