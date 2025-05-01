import os
import sys
import logging
from clang import cindex
from clang.cindex import CursorKind
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import lru_cache
import platform # For system include path detection

# Configure basic logging
logger = logging.getLogger(__name__)

# --- Libclang Initialization ---
LIBCLANG_PATH = os.environ.get("LIBCLANG_PATH")
LIBCLANG_INITIALIZED = False # Flag to track successful initialization

def get_namespace(cursor):
    """
    Walks up the semantic_parent chain to collect enclosing namespaces
    and class/struct scopes, then returns a '::'-joined string.
    """
    names = []
    cur = cursor.semantic_parent  # get the semantic parent
    while cur and cur.kind != CursorKind.TRANSLATION_UNIT:
        # Capture C++ namespace
        if cur.kind == CursorKind.NAMESPACE:
            names.append(cur.spelling)  # e.g. "foo" in namespace foo
        # Capture class/struct scopes for member functions
        elif cur.kind in (
            CursorKind.CLASS_DECL,
            CursorKind.STRUCT_DECL,
            CursorKind.CLASS_TEMPLATE,
            CursorKind.CXX_METHOD
        ):
            names.append(cur.spelling)
        cur = cur.semantic_parent  # recurse upward
    # Reverse to get outer→inner, then join with ::
    return "::".join(reversed(names))


# Function to attempt initialization
def _try_init_libclang(path):
    global LIBCLANG_INITIALIZED
    if LIBCLANG_INITIALIZED: return True # Already done
    if not path or not os.path.exists(path): return False
    try:
        cindex.Config.set_library_file(path)
        cindex.Index.create() # Test initialization
        logger.info(f"Libclang initialized successfully using: {path}")
        LIBCLANG_INITIALIZED = True
        return True
    except cindex.LibclangError as e:
        logger.warning(f"Failed to initialize libclang from {path}: {e}")
    except Exception as e:
         logger.warning(f"Unexpected error initializing libclang from {path}: {e}")
    return False

# Try initializing from environment variable first
if LIBCLANG_PATH:
    _try_init_libclang(LIBCLANG_PATH)

# If not initialized, try auto-detection
if not LIBCLANG_INITIALIZED:
    platform_paths = []
    system = platform.system()
    if system == "Linux":
        # Add more potential paths for different distributions/versions if needed
        platform_paths = [
            "/usr/lib/llvm-14/lib/libclang.so.1", "/usr/lib/llvm-15/lib/libclang.so.1",
            "/usr/lib/llvm-13/lib/libclang.so.1", "/usr/lib/libclang.so.1", "/usr/lib/libclang.so"
        ]
    elif system == "Darwin": # macOS
        platform_paths = [
            "/Library/Developer/CommandLineTools/usr/lib/libclang.dylib",
            "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/libclang.dylib"
        ]
    elif system == "Windows":
        platform_paths = ["C:\\Program Files\\LLVM\\bin\\libclang.dll"]

    for path in platform_paths:
        if _try_init_libclang(path):
            break # Stop after first successful initialization

if not LIBCLANG_INITIALIZED:
    logger.critical("Libclang initialization failed. Cannot proceed with parsing. Ensure libclang is installed and accessible, or set LIBCLANG_PATH.")
    # Optionally exit: sys.exit("Libclang initialization failed.")


# --- System Include Path ---
# Attempt to find a common system include path
SYSTEM_INCLUDE_PATH = None
if platform.system() == "Linux":
    if os.path.isdir("/usr/include"):
        SYSTEM_INCLUDE_PATH = "/usr/include"
elif platform.system() == "Darwin":
     # More robust check for CLT or Xcode includes
     clt_include = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include"
     xcode_base_sdk = "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include"
     if os.path.isdir(clt_include):
         SYSTEM_INCLUDE_PATH = clt_include
     elif os.path.isdir(xcode_base_sdk):
         SYSTEM_INCLUDE_PATH = xcode_base_sdk
# Windows path is complex, rely on clang finding them or user setting INCLUDE env var

if SYSTEM_INCLUDE_PATH:
     logger.info(f"Using system include path: {SYSTEM_INCLUDE_PATH}")
else:
     logger.warning("Could not determine standard system include path for this OS. Parsing might miss standard types like size_t.")


# --- Header File Discovery ---
HEADER_EXTENSIONS = {".h", ".hpp", ".hxx", ".hh", ".inl", ".tpp"} # Common C/C++ header/inline extensions
SKIP_DIRS = {".git", "build", "tests", "test", "testing", "examples", "example", "docs", "doc", "benchmark", "third_party", "external", "contrib", "tools"}
SKIP_DIR_PREFIXES = (".", "_") # Skip hidden dirs and often internal dirs like _build

@lru_cache(maxsize=None) # Cache results of finding headers per directory
def find_headers(base_dir: str) -> list[str]:
    """
    Recursively find all header files (based on HEADER_EXTENSIONS) in the directory.
    Skips common non-source directories and hidden directories. Optimized with caching.
    """
    headers = []
    logger.debug(f"Scanning for headers in: {base_dir}")
    try:
        for root, dirs, files in os.walk(base_dir, topdown=True):
            # Filter directories to skip
            dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS and not d.startswith(SKIP_DIR_PREFIXES)]

            for file in files:
                # Check extension case-insensitively
                if os.path.splitext(file)[1].lower() in HEADER_EXTENSIONS:
                    full_path = os.path.join(root, file)
                    # Basic check if it's likely a text file and readable
                    if os.path.isfile(full_path) and os.access(full_path, os.R_OK):
                        try:
                            with open(full_path, 'rb') as f: # Read as binary to check for null bytes
                                chunk = f.read(1024)
                                if b'\x00' in chunk:
                                    logger.debug(f"Skipping potentially binary file: {full_path}")
                                    continue
                            headers.append(full_path)
                        except (IOError, OSError) as e:
                            logger.warning(f"Could not read file {full_path}: {e}")
                        except Exception as e:
                             logger.warning(f"Unexpected error checking file {full_path}: {e}")
                    else:
                        logger.debug(f"Skipping non-file or non-readable item: {full_path}")

    except OSError as e:
        logger.warning(f"Could not access directory {base_dir} or its subdirectories: {e}")
    logger.debug(f"Found {len(headers)} headers in {base_dir}.")
    return headers


# --- Clang Parsing Logic (Worker Function) ---

def _get_argument_string(arg_cursor):
    """Helper to get a robust string representation of a function argument."""
    arg_type = arg_cursor.type.spelling or "[unknown_type]"
    arg_name = arg_cursor.spelling
    # Handle common cases like 'int' vs 'int name'
    if arg_name:
        # Avoid cases where type includes the name (e.g., function pointers)
        # This is heuristic and might not cover all cases
        if not arg_name.startswith(arg_type.split()[0]):
             return f"{arg_type} {arg_name}"
    return arg_type


def _parse_and_extract_worker(header_path: str, include_paths: tuple[str]) -> list[dict] | None:
    """
    Worker function for ProcessPoolExecutor. Parses a single header and extracts functions.
    Returns a list of function dicts (picklable) or None on fatal error.
    """
    if not LIBCLANG_INITIALIZED: return None

    # Ensure libclang is re-initialized in the new process if necessary
    # This might be needed depending on how ProcessPoolExecutor handles globals/modules
    # Re-running the init check within the worker is safer.
    if not _try_init_libclang(LIBCLANG_PATH): # Try env var first
         # Try auto-detection again within the worker if env var failed
         system = platform.system()
         platform_paths = []
         if system == "Linux": platform_paths = ["/usr/lib/llvm-14/lib/libclang.so.1", "/usr/lib/libclang.so"]
         elif system == "Darwin": platform_paths = ["/Library/Developer/CommandLineTools/usr/lib/libclang.dylib", "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/libclang.dylib"]
         elif system == "Windows": platform_paths = ["C:\\Program Files\\LLVM\\bin\\libclang.dll"]
         found_in_worker = False
         for p in platform_paths:
              if _try_init_libclang(p):
                   found_in_worker = True
                   break
         if not found_in_worker:
              logger.error(f"Libclang could not be initialized in worker process for {header_path}. Skipping.")
              return None


    try:
        index = cindex.Index.create()
        # Base arguments
        args = ['-x', 'c++', '-std=c++11', '-Wno-pragma-once-outside-header']
        # Add provided include paths (repo-specific)
        args.extend([f'-I{p}' for p in include_paths if os.path.isdir(p)])
        # Add header's own directory
        header_dir = os.path.dirname(header_path)
        # Check if header_dir is already covered by include_paths (e.g., repo_path itself)
        if header_dir not in include_paths and os.path.isdir(header_dir):
             args.append(f'-I{header_dir}')
        # Add system include path if found
        if SYSTEM_INCLUDE_PATH and os.path.isdir(SYSTEM_INCLUDE_PATH):
             args.append(f'-isystem{SYSTEM_INCLUDE_PATH}')

        # Define common macros that might hide types (heuristic)
        # This helps clang resolve types like size_t if headers aren't perfect
        # Add more as needed based on common library patterns
        common_defines = ['-Dsize_t=unsigned long', '-Duint32_t="unsigned int"'] # Example defines
        args.extend(common_defines)


        # Parse with options
        tu = index.parse(header_path, args=args,
                         options=cindex.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES |
                                 cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD |
                                 cindex.TranslationUnit.PARSE_INCOMPLETE)

        if not tu:
             logger.error(f"Failed to create translation unit for {header_path} (returned None).")
             return None # Indicate failure

        # Check for fatal errors, but proceed if incomplete parsing allowed
        fatal_errors = [d for d in tu.diagnostics if d.severity >= cindex.Diagnostic.Error]
        if fatal_errors:
             # Log only if level is DEBUG or higher to avoid spamming INFO logs
             if logger.isEnabledFor(logging.DEBUG):
                  errors_summary = [f"({d.location.line}:{d.location.column}) {d.spelling}" for d in fatal_errors[:5]] # Limit summary
                  logger.debug(f"Parsing errors encountered in {header_path}. Results might be incomplete. Errors: {errors_summary}")
             else:
                  logger.warning(f"Parsing errors encountered in {header_path}. Results might be incomplete. Set log level to DEBUG for details.")


        # --- Extraction Logic (moved inside worker) ---
        functions = []
        processed_signatures = set()
        if tu.cursor: # Check if cursor is valid
            for cursor in tu.cursor.walk_preorder():
                 # Also consider FUNCTION_TEMPLATE? Might be too complex for now.
                if cursor.kind == cindex.CursorKind.FUNCTION_DECL:
                    # Check location validity before accessing file attribute
                    if not cursor.location or not cursor.location.file:
                        continue

                    # Ensure it's a declaration (not definition) and located in the target file
                    if (cursor.location.file.name == header_path and
                        not cursor.is_definition()):

                        func_name = cursor.spelling
                        # print(func_name) # Removed noisy print
                        if not func_name: continue # Skip anonymous functions or parsing artifacts

                        params = []
                        try:
                            # Iterate through arguments using get_arguments() if available
                            for arg in cursor.get_arguments():
                                params.append(_get_argument_string(arg))
                        except Exception as arg_err:
                            # Fallback or log if get_arguments fails
                            logger.debug(f"Could not get arguments for {func_name} in {header_path} using get_arguments(): {arg_err}. Trying children.")
                            # Sometimes arguments are children, not accessible via get_arguments()
                            # This is less reliable but can be a fallback
                            child_params = []
                            for child in cursor.get_children():
                                if child.kind == cindex.CursorKind.PARM_DECL:
                                     child_params.append(_get_argument_string(child))
                            if child_params:
                                 params = child_params
                            else:
                                 params = ["..."] # Indicate potential issue or complex signature

                        ns = get_namespace(cursor)
                        full_name = f"{ns}::{func_name}" if ns else func_name

                        signature = f"{full_name}({','.join(params)})" # Use full_name in signature for uniqueness
                        if signature not in processed_signatures:
                            return_type = cursor.result_type.spelling or "[unknown_type]"
                            function_info = {
                                "name":        func_name, # Keep original name without namespace here if needed elsewhere
                                "namespace":   ns or None,
                                "full_name":   full_name, # Store name with namespace
                                "return_type": return_type,
                                "parameters":  params,
                                "filepath":    header_path, # For context, removed by db_builder later
                                "line":        cursor.location.line # For context, removed later
                            }

                            functions.append(function_info)
                            processed_signatures.add(signature)
        # --- End Extraction Logic ---

        return functions # Return the picklable list

    except cindex.TranslationUnitLoadError as e:
         logger.error(f"Fatal error loading translation unit for {header_path}: {e}")
         return None
    except Exception as e:
         # Log exception with traceback for better debugging
         logger.error(f"Unexpected error parsing/extracting header {header_path}: {e}", exc_info=True)
         return None


# --- Main Parsing Orchestration ---

def parse_repo_headers(repo_path: str, max_workers: int | None = None) -> list[dict]:
    """
    Finds all headers in a repository and parses them in parallel to extract function declarations.
    Uses ProcessPoolExecutor with a worker function that returns picklable results.
    Returns a list of unique function dictionaries found across all headers.
    """
    if not LIBCLANG_INITIALIZED:
        logger.error("Cannot parse repository headers because libclang failed to initialize.")
        return []

    all_functions_map = {} # Use dict to easily handle uniqueness across files {full_signature: function_info}

    header_files = find_headers(repo_path)
    if not header_files:
        logger.warning(f"No header files found in '{repo_path}'.")
        return []

    logger.info(f"Found {len(header_files)} headers in '{os.path.basename(repo_path)}'. Starting parallel parsing...")

    # Determine include paths (simple approach: use the repo root and common dirs)
    potential_include_dirs = ['include', 'src', 'lib', 'core', 'inc'] # Added 'inc'
    include_paths = [repo_path] + [os.path.join(repo_path, d) for d in potential_include_dirs if os.path.isdir(os.path.join(repo_path, d))]
    include_paths_tuple = tuple(include_paths) # Convert to tuple for worker arg

    num_cpus = os.cpu_count() or 1
    # Adjust workers based on available CPUs and number of files
    # Limit workers to avoid overwhelming system, especially if memory is constrained
    max_allowed_workers = max(1, num_cpus // 2) # Heuristic: use half the CPUs
    actual_workers = min(max_workers or max_allowed_workers, len(header_files), max_allowed_workers)
    logger.info(f"Using {actual_workers} workers for parsing (max allowed: {max_allowed_workers}).")

    # Use ProcessPoolExecutor with the dedicated worker function
    # Consider adding a timeout to futures?
    with ProcessPoolExecutor(max_workers=actual_workers) as executor:
        future_to_header = {
            executor.submit(_parse_and_extract_worker, header, include_paths_tuple): header
            for header in header_files
        }

        processed_count = 0
        total_headers = len(future_to_header)

        for future in as_completed(future_to_header):
            header_path = future_to_header[future]
            processed_count += 1
            if processed_count % 50 == 0 or processed_count == total_headers: # Update less frequently
                 logger.info(f"  Parsing progress: {processed_count}/{total_headers} headers processed...")

            try:
                # Result is now the list of dicts (or None)
                functions_in_file = future.result() # Timeout possible here? future.result(timeout=...)
                if functions_in_file:
                    # Add unique functions to the global map
                    for func in functions_in_file:
                        # Signature for uniqueness check (using full name now)
                        signature = f"{func['full_name']}({','.join(func['parameters'])})"
                        # If not seen before, or if new one has more info (e.g., better params), add/update
                        # Prioritize entries with actual parameters over placeholders like '...'
                        if signature not in all_functions_map or \
                           (all_functions_map[signature]['parameters'] == ['...'] and func['parameters'] != ['...']):
                             all_functions_map[signature] = func
            except TimeoutError:
                 logger.error(f"Parsing timed out for header {header_path}")
            except Exception as e:
                logger.error(f"Error processing result for header {header_path}: {e}", exc_info=True)

    final_function_list = list(all_functions_map.values())
    logger.info(f"Finished parsing for '{os.path.basename(repo_path)}'. Extracted {len(final_function_list)} unique function declarations.")
    return final_function_list
