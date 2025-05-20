import os
import sys
import logging
from clang import cindex
from clang.cindex import CursorKind
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import lru_cache
import platform

logger = logging.getLogger(__name__)

LIBCLANG_PATH = os.environ.get("LIBCLANG_PATH")
LIBCLANG_INITIALIZED = False

def get_namespace(cursor):
    names = []
    cur = cursor.semantic_parent
    while cur and cur.kind != CursorKind.TRANSLATION_UNIT:
        if cur.kind == CursorKind.NAMESPACE:
            names.append(cur.spelling)
        elif cur.kind in (
            CursorKind.CLASS_DECL,
            CursorKind.STRUCT_DECL,
            CursorKind.CLASS_TEMPLATE,
            CursorKind.CXX_METHOD
        ):
            names.append(cur.spelling)
        cur = cur.semantic_parent
    return "::".join(reversed(names))

def _try_init_libclang(path):
    global LIBCLANG_INITIALIZED
    if LIBCLANG_INITIALIZED: return True
    if not path or not os.path.exists(path): return False
    try:
        cindex.Config.set_library_file(path)
        cindex.Index.create()
        logger.info(f"Libclang initialized successfully using: {path}")
        LIBCLANG_INITIALIZED = True
        return True
    except cindex.LibclangError as e:
        logger.warning(f"Failed to initialize libclang from {path}: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error initializing libclang from {path}: {e}")
    return False

if LIBCLANG_PATH:
    _try_init_libclang(LIBCLANG_PATH)

if not LIBCLANG_INITIALIZED:
    platform_paths = []
    system = platform.system()
    if system == "Linux":
        platform_paths = [
            "/usr/lib/llvm-14/lib/libclang.so.1", "/usr/lib/llvm-15/lib/libclang.so.1",
            "/usr/lib/llvm-13/lib/libclang.so.1", "/usr/lib/libclang.so.1", "/usr/lib/libclang.so"
        ]
    elif system == "Darwin":
        platform_paths = [
            "/Library/Developer/CommandLineTools/usr/lib/libclang.dylib",
            "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/libclang.dylib"
        ]
    elif system == "Windows":
        platform_paths = ["C:\\Program Files\\LLVM\\bin\\libclang.dll"]

    for path in platform_paths:
        if _try_init_libclang(path):
            break

if not LIBCLANG_INITIALIZED:
    logger.critical("Libclang initialization failed. Ensure libclang is installed and accessible, or set LIBCLANG_PATH.")

SYSTEM_INCLUDE_PATH = None
if platform.system() == "Linux":
    if os.path.isdir("/usr/include"):
        SYSTEM_INCLUDE_PATH = "/usr/include"
elif platform.system() == "Darwin":
    clt_include = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include"
    xcode_base_sdk = "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include"
    if os.path.isdir(clt_include):
        SYSTEM_INCLUDE_PATH = clt_include
    elif os.path.isdir(xcode_base_sdk):
        SYSTEM_INCLUDE_PATH = xcode_base_sdk

HEADER_EXTENSIONS = {".h", ".hpp", ".hxx", ".hh", ".inl", ".tpp"}
SKIP_DIRS = {".git", "build", "tests", "test", "testing", "examples", "example", "docs", "doc", "benchmark", "third_party", "external", "contrib", "tools"}
SKIP_DIR_PREFIXES = (".", "_")

@lru_cache(maxsize=None)
def find_headers(base_dir: str) -> list[str]:
    headers = []
    try:
        for root, dirs, files in os.walk(base_dir, topdown=True):
            dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS and not d.startswith(SKIP_DIR_PREFIXES)]
            for file in files:
                if os.path.splitext(file)[1].lower() in HEADER_EXTENSIONS:
                    full_path = os.path.join(root, file)
                    if os.path.isfile(full_path) and os.access(full_path, os.R_OK):
                        try:
                            with open(full_path, 'rb') as f:
                                chunk = f.read(1024)
                                if b'\x00' in chunk:
                                    continue
                            headers.append(full_path)
                        except Exception:
                            pass
    except OSError as e:
        logger.warning(f"Could not access directory {base_dir}: {e}")
    return headers

def _get_argument_string(arg_cursor):
    arg_type = arg_cursor.type.spelling or "[unknown_type]"
    arg_name = arg_cursor.spelling
    if arg_name:
        if not arg_name.startswith(arg_type.split()[0]):
            return f"{arg_type} {arg_name}"
    return arg_type

def _parse_and_extract_worker(header_path: str, include_paths: tuple[str]) -> list[dict] | None:
    if not LIBCLANG_INITIALIZED: return None
    try:
        index = cindex.Index.create()
        args = ['-x', 'c++', '-std=c++11', '-Wno-pragma-once-outside-header']
        args.extend([f'-I{p}' for p in include_paths if os.path.isdir(p)])
        header_dir = os.path.dirname(header_path)
        if header_dir not in include_paths and os.path.isdir(header_dir):
            args.append(f'-I{header_dir}')
        if SYSTEM_INCLUDE_PATH and os.path.isdir(SYSTEM_INCLUDE_PATH):
            args.append(f'-isystem{SYSTEM_INCLUDE_PATH}')
        common_defines = ['-Dsize_t=unsigned long', '-Duint32_t="unsigned int"']
        args.extend(common_defines)
        tu = index.parse(header_path, args=args,
                         options=cindex.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES |
                                 cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD |
                                 cindex.TranslationUnit.PARSE_INCOMPLETE)
        if not tu:
            return None
        functions = []
        processed_signatures = set()
        if tu.cursor:
            for cursor in tu.cursor.walk_preorder():
                if cursor.kind == cindex.CursorKind.FUNCTION_DECL:
                    if not cursor.location or not cursor.location.file:
                        continue
                    if (cursor.location.file.name == header_path and
                        not cursor.is_definition()):
                        func_name = cursor.spelling
                        if not func_name: continue
                        params = []
                        try:
                            for arg in cursor.get_arguments():
                                params.append(_get_argument_string(arg))
                        except Exception:
                            params = ["..."]
                        ns = get_namespace(cursor)
                        full_name = f"{ns}::{func_name}" if ns else func_name
                        signature = f"{full_name}({','.join(params)})"
                        if signature not in processed_signatures:
                            return_type = cursor.result_type.spelling or "[unknown_type]"
                            function_info = {
                                "name":        func_name,
                                "namespace":   ns or None,
                                "full_name":   full_name,
                                "return_type": return_type,
                                "parameters":  params,
                                "filepath":    header_path,
                                "line":        cursor.location.line
                            }
                            functions.append(function_info)
                            processed_signatures.add(signature)
        return functions
    except Exception:
        return None

def parse_repo_headers(repo_path: str, max_workers: int | None = None) -> list[dict]:
    if not LIBCLANG_INITIALIZED:
        logger.error("Cannot parse repository headers because libclang failed to initialize.")
        return []
    all_functions_map = {}
    header_files = find_headers(repo_path)
    if not header_files:
        logger.warning(f"No header files found in '{repo_path}'.")
        return []
    logger.info(f"Found {len(header_files)} headers in '{os.path.basename(repo_path)}'. Starting parallel parsing...")
    potential_include_dirs = ['include', 'src', 'lib', 'core', 'inc']
    include_paths = [repo_path] + [os.path.join(repo_path, d) for d in potential_include_dirs if os.path.isdir(os.path.join(repo_path, d))]
    include_paths_tuple = tuple(include_paths)
    num_cpus = os.cpu_count() or 1
    max_allowed_workers = max(1, num_cpus // 2)
    actual_workers = min(max_workers or max_allowed_workers, len(header_files), max_allowed_workers)
    logger.info(f"Using {actual_workers} workers for parsing.")
    with ProcessPoolExecutor(max_workers=actual_workers) as executor:
        future_to_header = {
            executor.submit(_parse_and_extract_worker, header, include_paths_tuple): header
            for header in header_files
        }
        for future in as_completed(future_to_header):
            header_path = future_to_header[future]
            try:
                functions_in_file = future.result()
                if functions_in_file:
                    for func in functions_in_file:
                        signature = f"{func['full_name']}({','.join(func['parameters'])})"
                        if signature not in all_functions_map or \
                           (all_functions_map[signature]['parameters'] == ['...'] and func['parameters'] != ['...']):
                            all_functions_map[signature] = func
            except Exception:
                pass
    final_function_list = list(all_functions_map.values())
    logger.info(f"Finished parsing for '{os.path.basename(repo_path)}'. Extracted {len(final_function_list)} unique function declarations.")
    return final_function_list
