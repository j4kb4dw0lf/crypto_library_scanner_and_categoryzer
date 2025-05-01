import os
import re
import logging
import requests # For GitHub API calls
from functools import lru_cache
from urllib.parse import urlparse
from packaging import version as packaging_version # For version comparison
import time

# Configure basic logging
logger = logging.getLogger(__name__)

# --- GitHub API Version Fetching ---

def _extract_owner_repo(repo_url: str) -> tuple[str | None, str | None]:
    """Extracts owner and repo name from various GitHub URL formats."""
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
    """
    Fetches tags from the GitHub API and returns the latest valid version tag.
    Handles rate limiting and errors gracefully. Handles different tag formats.
    """
    if not owner or not repo:
        return None

    api_url = f"https://api.github.com/repos/{owner}/{repo}/tags"
    logger.debug(f"Fetching tags from GitHub API: {api_url}")

    try:
        headers = {'User-Agent': 'Crypto-Scanner-Bot'} # Basic User-Agent
        # Consider adding PAT for higher rate limits:
        # pat = os.environ.get('GITHUB_PAT')
        # if pat: headers['Authorization'] = f'token {pat}'

        response = requests.get(api_url, headers=headers, timeout=15)

        # Check for rate limiting
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

        # Log other non-200 responses
        if response.status_code != 200:
             logger.warning(f"GitHub API request for {owner}/{repo} tags failed with status {response.status_code}: {response.text[:200]}")

        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx) if not handled above

        tags_data = response.json()
        if not isinstance(tags_data, list):
             logger.warning(f"Unexpected API response format for tags: {tags_data}")
             return None

        valid_versions = []
        for tag_info in tags_data:
            tag_name = tag_info.get('name')
            if not tag_name: continue

            version_part = None
            # Try to extract version from common patterns
            # 1. Standard vX.Y.Z or X.Y.Z
            match_std = re.match(r'^[vV]?(\d+(\.\d+)+.*)', tag_name)
            # 2. LibraryName_X_Y_Z (like CRYPTOPP_8_9_0)
            match_lib = re.match(r'^[a-zA-Z_-]+_(\d+_\d+_\d+)$', tag_name)
            # 3. LibraryName-X.Y.Z (like openssl-3.0.0)
            match_lib_dash = re.match(r'^[a-zA-Z_-]+-([\d]+(\.\d+)+.*)', tag_name)

            if match_std:
                version_part = match_std.group(1)
            elif match_lib:
                version_part = match_lib.group(1).replace('_', '.') # Convert X_Y_Z to X.Y.Z
            elif match_lib_dash:
                 version_part = match_lib_dash.group(1)
            else:
                logger.debug(f"Tag '{tag_name}' doesn't match known version patterns.")
                continue

            try:
                # Use packaging.version to parse and allow comparison
                parsed_ver = packaging_version.parse(version_part)
                valid_versions.append(parsed_ver)
            except packaging_version.InvalidVersion:
                logger.debug(f"Could not parse tag '{tag_name}' (part: '{version_part}') as a valid version.")
                continue

        if not valid_versions:
            logger.info(f"No valid version tags found via GitHub API for {owner}/{repo}.")
            return None

        # Sort versions (latest first)
        valid_versions.sort(reverse=True)

        # Prioritize non-pre-release versions if available
        latest_stable = next((v for v in valid_versions if not v.is_prerelease), None)
        if latest_stable:
             latest_version = str(latest_stable)
             logger.info(f"Latest stable version tag found via GitHub API for {owner}/{repo}: {latest_version}")
        else:
             # If only pre-releases found, take the latest one
             latest_version = str(valid_versions[0])
             logger.info(f"Latest version tag (pre-release) found via GitHub API for {owner}/{repo}: {latest_version}")

        return latest_version

    except requests.exceptions.RequestException as e:
        logger.error(f"Network error fetching tags from GitHub API for {owner}/{repo}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error processing GitHub tags for {owner}/{repo}: {e}", exc_info=True)
        return None


# --- Library Info Extraction (Local Files) ---

@lru_cache(maxsize=128) # Cache results for file reads
def read_file_content(filepath: str) -> str | None:
    """Reads the content of a file, caching the result."""
    try:
        # Try UTF-8 first, then fallback with error handling
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except FileNotFoundError:
        return None
    except (IOError, OSError) as e: # Catch OS errors too
        logger.warning(f"Could not read file {filepath}: {e}")
        return None
    except Exception as e:
         logger.warning(f"Unexpected error reading file {filepath}: {e}")
         return None


def find_first_file(base_dir: str, filenames: list[str]) -> str | None:
    """Finds the first existing file from a list within the base directory."""
    for filename in filenames:
        filepath = os.path.join(base_dir, filename)
        if os.path.isfile(filepath):
            return filepath
    return None

def extract_from_cmake(content: str) -> tuple[str | None, str | None]:
    """Extracts project name and version from CMakeLists.txt content."""
    name = None
    version = None
    # Match project(Name VERSION X.Y.Z...) or project(Name X.Y.Z...)
    # Make version capture group more flexible
    match = re.search(r'project\s*\(\s*(\w+)\s*(?:VERSION\s+)?([\w\d\.\-]+)', content, re.IGNORECASE)
    if match:
        name = match.group(1)
        version_str = match.group(2)
        # Basic validation that it looks like a version
        if re.match(r'^[\d\.]', version_str):
             version = version_str
             logger.debug(f"Extracted from CMake: name='{name}', version='{version}'")
    return name, version

def extract_from_configure_ac(content: str) -> tuple[str | None, str | None]:
    """Extracts project name and version from configure.ac content."""
    name = None
    version = None
    # Match AC_INIT([Name], [X.Y.Z...], ...)
    match = re.search(r'AC_INIT\s*\(\s*\[([^\]]+)\]\s*,\s*\[([^\]]+)\]', content)
    if match:
        name = match.group(1).strip() # Strip potential whitespace
        version_str = match.group(2).strip()
        if re.match(r'^[\d\.]', version_str): # Basic validation
             version = version_str
             logger.debug(f"Extracted from configure.ac: name='{name}', version='{version}'")
    return name, version

def extract_from_version_file(content: str) -> str | None:
    """Extracts version from a simple VERSION file content."""
    lines = content.strip().splitlines()
    if lines:
        version_str = lines[0].strip().lstrip('vV')
        # Basic sanity check for version format (e.g., X.Y.Z, allow suffixes)
        if re.match(r'^[\d\.]+[a-zA-Z0-9._-]*$', version_str):
            logger.debug(f"Extracted from VERSION file: version='{version_str}'")
            return version_str
    return None

# --- Main Info Function ---

def get_library_info(repo_path: str, repo_name: str, repo_url: str | None = None) -> tuple[str, str | None]:
    """
    Attempts to automatically detect the library name and version.
    Checks local files first, then falls back to GitHub API if repo_url is provided.
    Returns (detected_name, detected_version | None).
    Uses the repo_name as a fallback name.
    """
    detected_name = repo_name # Default to repo name
    detected_version = None

    # --- Step 1: Check Local Files ---
    logger.debug(f"Checking local files for version info in {repo_path}")
    check_files = [
        ("CMakeLists.txt", extract_from_cmake),
        ("configure.ac", extract_from_configure_ac),
        ("VERSION", extract_from_version_file),
        ("version.txt", extract_from_version_file),
        (".version", extract_from_version_file),
        # Add more specific files if needed (e.g., setup.py, package.json require different extractors)
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
                    # If we found both from a reliable source, break early? Maybe not, VERSION file might be more accurate.
                    # Let's check all local files first.

    # Assign locally found values
    if found_name_local: detected_name = found_name_local
    detected_version = found_version_local # Will be None if not found

    logger.info(f"Local file check result: Name='{detected_name}', Version='{detected_version or 'Not Found'}'")

    # --- Step 2: Fallback to GitHub API if version not found locally ---
    if not detected_version and repo_url:
        logger.info(f"Version not found locally. Attempting GitHub API fallback for {repo_url}")
        owner, repo = _extract_owner_repo(repo_url)
        if owner and repo:
            api_version = fetch_latest_github_tag(owner, repo)
            if api_version:
                detected_version = api_version
        else:
            logger.warning(f"Could not extract owner/repo from URL '{repo_url}' for API lookup.")

    # Final result
    logger.info(f"Final library info: Name='{detected_name}', Version='{detected_version or 'Not Found'}'")
    return detected_name, detected_version


# Example usage (optional, for testing)
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG) # Enable debug for testing
    logger.setLevel(logging.DEBUG)

    # Test local file extraction
    print("\n--- Local File Tests ---")
    os.makedirs("test_repo_cmake", exist_ok=True)
    with open("test_repo_cmake/CMakeLists.txt", "w") as f: f.write("project(MyCMakeLib VERSION 1.2.3)")
    name, version = get_library_info("test_repo_cmake", "test_repo_cmake")
    print(f"CMake Test: Name={name}, Version={version}")

    os.makedirs("test_repo_configure", exist_ok=True)
    with open("test_repo_configure/configure.ac", "w") as f: f.write("AC_INIT([MyConfigureLib], [2.0.0])")
    name, version = get_library_info("test_repo_configure", "test_repo_configure")
    print(f"Configure Test: Name={name}, Version={version}")

    os.makedirs("test_repo_version", exist_ok=True)
    with open("test_repo_version/VERSION", "w") as f: f.write("v3.5-beta")
    name, version = get_library_info("test_repo_version", "test_repo_version")
    print(f"Version Test: Name={name}, Version={version}")

    # Test GitHub API fallback (replace with actual repos if needed, will hit API)
    print("\n--- GitHub API Tests (will make actual API calls) ---")
    # Example 1: Repo with clear tags (requests library)
    requests_url = "https://github.com/psf/requests.git"
    name, version = get_library_info("nonexistent_local_path", "requests", requests_url)
    print(f"Requests Test: Name={name}, Version={version}") # Should find a version like 2.x.x

    # Example 2: Repo with potentially complex tags (OpenSSL)
    openssl_url = "https://github.com/openssl/openssl.git"
    name, version = get_library_info("nonexistent_local_path", "openssl", openssl_url)
    print(f"OpenSSL Test: Name={name}, Version={version}") # Should find a version like 3.x.x or 1.x.x

     # Example 3: Repo with no standard version files or tags (might return None)
    some_repo_url = "https://github.com/google/googletest.git" # Googletest uses releases, maybe tags too?
    name, version = get_library_info("nonexistent_local_path", "googletest", some_repo_url)
    print(f"Googletest Test: Name={name}, Version={version}")

    # Example 4: Crypto++ test
    cryptopp_url = "https://github.com/weidai11/cryptopp.git"
    name, version = get_library_info("nonexistent_local_path", "cryptopp", cryptopp_url)
    print(f"Crypto++ Test: Name={name}, Version={version}") # Should hopefully find 8.9.0 or similar


    # Clean up dummy files
    import shutil
    shutil.rmtree("test_repo_cmake")
    shutil.rmtree("test_repo_configure")
    shutil.rmtree("test_repo_version")
