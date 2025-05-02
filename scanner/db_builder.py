import json
import os
import logging
from datetime import datetime, timezone
from operator import itemgetter
from .category_matcher import classify, is_quantum_safe

logger = logging.getLogger(__name__)

OUTPUT_DIR = "output"
PRIMITIVES_FILE = os.path.join(OUTPUT_DIR, "primitives.json")
UNCATEGORIZED_PRIMITIVES_FILE = os.path.join(OUTPUT_DIR, "uncategorized_primitives.json")
LIBRARIES_FILE = os.path.join(OUTPUT_DIR, "libraries.json")

def load_json(filepath: str) -> list | dict:
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if not isinstance(data, list):
                logger.warning(f"Data in {filepath} is not a list. Reinitializing as empty list.")
                return []
            return data
    except (json.JSONDecodeError, IOError, Exception) as e:
        logger.error(f"Error loading JSON from {filepath}: {e}. Returning empty list.")
        return []

def save_json(data: list | dict, filepath: str):
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.debug(f"Successfully saved data to {filepath}")
    except (IOError, TypeError, Exception) as e:
        logger.error(f"Error saving JSON to {filepath}: {e}")

def build_database(repo_results: list[dict], external_results: list[dict]):
    global PRIMITIVES_FILE, UNCATEGORIZED_PRIMITIVES_FILE, LIBRARIES_FILE
    logger.info(f"Building/Updating JSON database files: {LIBRARIES_FILE}, {PRIMITIVES_FILE}, {UNCATEGORIZED_PRIMITIVES_FILE}")

    primitives_db = load_json(PRIMITIVES_FILE)
    uncategorized_db = load_json(UNCATEGORIZED_PRIMITIVES_FILE)
    libraries_db = load_json(LIBRARIES_FILE)

    existing_libs = {(lib.get('name'), lib.get('version')): index for index, lib in enumerate(libraries_db)}
    existing_primitives = {
        (p.get('library'), p.get('name'), tuple(p.get('parameters', []))): index
        for index, p in enumerate(primitives_db + uncategorized_db)
    }

    lib_id_counter = max([lib.get('library_id', 0) for lib in libraries_db] + [0]) + 1
    primitive_id_counter = max([p.get('id', 0) for p in primitives_db + uncategorized_db] + [0]) + 1

    processed_repo_count = new_primitives_count = updated_primitives_count = 0
    new_libs_count = updated_libs_count = 0

    processed_primitives = {}
    processed_keys_in_run = set()

    for result in repo_results:
        repo_name = result.get('repo_name')
        library_name = result.get('library_name')
        library_version = result.get('library_version')
        repo_url = result.get('repo_url')
        local_repo_path = result.get('local_path')
        functions = result.get('functions', [])

        if not repo_name or not library_name or not local_repo_path:
            logger.warning(f"Skipping result due to missing fields: {result.get('repo_url')}")
            continue

        processed_repo_count += 1
        logger.info(f"Processing: {library_name} (Version: {library_version or 'Unknown'}) from {repo_name}")

        lib_key = (library_name, library_version)
        current_time_iso = datetime.now(timezone.utc).isoformat()

        if lib_key in existing_libs:
            lib_index = existing_libs[lib_key]
            current_lib_entry = libraries_db[lib_index]
            updated = False
            if current_lib_entry.get('source_url') != repo_url:
                current_lib_entry['source_url'] = repo_url
                updated = True
            current_lib_entry['last_updated'] = current_time_iso
            if updated: updated_libs_count += 1
            library_id = current_lib_entry['library_id']
        else:
            library_id = lib_id_counter
            libraries_db.append({
                "library_id": library_id,
                "name": library_name,
                "version": library_version,
                "source_url": repo_url,
                "scan_date": current_time_iso,
                "last_updated": current_time_iso,
            })
            existing_libs[lib_key] = len(libraries_db) - 1
            lib_id_counter += 1
            new_libs_count += 1

        for func in functions:
            func_name = func.get('full_name')
            filepath = func.get('filepath')
            if not func_name or not filepath:
                continue
            if "::operator" in func_name or "operator" in func_name:
                continue

            params_list = func.get('parameters', [])
            if not isinstance(params_list, list):
                params_list = []
            params_tuple = tuple(params_list)
            primitive_key = (library_name, func_name, params_tuple)
            processed_keys_in_run.add(primitive_key)

            header_filename_base = os.path.splitext(os.path.basename(filepath))[0]
            namespace = func_name.split("::")[0] if "::" in func_name else header_filename_base
            category = classify(func_name, namespace, library_name)
            is_post_quantum_safe = is_quantum_safe(func_name, namespace, library_name)

            existing_index = existing_primitives.get(primitive_key)
            is_update = existing_index is not None
            target_entry = (primitives_db + uncategorized_db)[existing_index] if is_update else {}

            primitive_data = {
                "id": target_entry.get('id', primitive_id_counter),
                "name": func_name,
                "library": library_name,
                "library_version_found_in": library_version,
                "category": category,
                "primitive_group": namespace,
                "is_post_quantum_safe": is_post_quantum_safe,
                "parameters": params_list,
                "return_type": func.get('return_type'),
            }

            if is_update:
                if (target_entry.get('library_version_found_in') != library_version or
                    target_entry.get('category') != category or
                    target_entry.get('primitive_group') != namespace):
                    processed_primitives[primitive_key] = primitive_data
                    updated_primitives_count += 1
                else:
                    processed_primitives[primitive_key] = target_entry
            else:
                processed_primitives[primitive_key] = primitive_data
                primitive_id_counter += 1
                new_primitives_count += 1

    for result in external_results:
        repo_name = result.get('external_lib_name')
        library_name = result.get('library_name')
        library_version = result.get('library_version')
        repo_url = result.get('external_lib_path')
        local_repo_path = result.get('local_path')
        functions = result.get('functions', [])

        if not repo_name or not library_name or not local_repo_path:
            logger.warning(f"Skipping result due to missing fields: {result.get('repo_url')}")
            continue

        processed_repo_count += 1
        logger.info(f"Processing: {library_name} (Version: {library_version or 'Unknown'}) from {repo_name}")

        lib_key = (library_name, library_version)
        current_time_iso = datetime.now(timezone.utc).isoformat()

        if lib_key in existing_libs:
            lib_index = existing_libs[lib_key]
            current_lib_entry = libraries_db[lib_index]
            updated = False
            if current_lib_entry.get('source_url') != repo_url:
                current_lib_entry['source_url'] = repo_url
                updated = True
            current_lib_entry['last_updated'] = current_time_iso
            if updated: updated_libs_count += 1
            library_id = current_lib_entry['library_id']
        else:
            library_id = lib_id_counter
            libraries_db.append({
                "library_id": library_id,
                "name": library_name,
                "version": library_version,
                "source_url": repo_url,
                "scan_date": current_time_iso,
                "last_updated": current_time_iso,
            })
            existing_libs[lib_key] = len(libraries_db) - 1
            lib_id_counter += 1
            new_libs_count += 1

        for func in functions:
            func_name = func.get('full_name')
            filepath = func.get('filepath')
            if not func_name or not filepath:
                continue
            if "::operator" in func_name or "operator" in func_name:
                continue

            params_list = func.get('parameters', [])
            if not isinstance(params_list, list):
                params_list = []
            params_tuple = tuple(params_list)
            primitive_key = (library_name, func_name, params_tuple)
            processed_keys_in_run.add(primitive_key)

            header_filename_base = os.path.splitext(os.path.basename(filepath))[0]
            namespace = func_name.split("::")[0] if "::" in func_name else header_filename_base
            category = classify(func_name, namespace, library_name)
            is_post_quantum_safe = is_quantum_safe(func_name, namespace, library_name)

            existing_index = existing_primitives.get(primitive_key)
            is_update = existing_index is not None
            target_entry = (primitives_db + uncategorized_db)[existing_index] if is_update else {}

            primitive_data = {
                "id": target_entry.get('id', primitive_id_counter),
                "name": func_name,
                "library": library_name,
                "library_version_found_in": library_version,
                "category": category,
                "primitive_group": namespace,
                "is_post_quantum_safe": is_post_quantum_safe,
                "parameters": params_list,
                "return_type": func.get('return_type'),
            }

            if is_update:
                if (target_entry.get('library_version_found_in') != library_version or
                    target_entry.get('category') != category or
                    target_entry.get('primitive_group') != namespace):
                    processed_primitives[primitive_key] = primitive_data
                    updated_primitives_count += 1
                else:
                    processed_primitives[primitive_key] = target_entry
            else:
                processed_primitives[primitive_key] = primitive_data
                primitive_id_counter += 1
                new_primitives_count += 1

    final_primitives = []
    final_uncategorized = []

    for primitive in processed_primitives.values():
        if primitive.get("category") == "uncategorized":
            final_uncategorized.append(primitive)
        else:
            final_primitives.append(primitive)

    for key, index in existing_primitives.items():
        if key not in processed_keys_in_run:
            old = (primitives_db + uncategorized_db)[index]
            old.pop('filepath', None)
            old.pop('line', None)
            group = old.get('primitive_group', '')
            if '.' in group:
                old['primitive_group'] = os.path.splitext(group)[0]
            elif group == '':
                old['primitive_group'] = 'unknown'
            if old.get("category") == "uncategorized":
                final_uncategorized.append(old)
            else:
                final_primitives.append(old)

    final_primitives.sort(key=lambda x: (x.get('library', ''), x.get('primitive_group', ''), x.get('name', '')))
    final_uncategorized.sort(key=lambda x: (x.get('library', ''), x.get('primitive_group', ''), x.get('name', '')))

    logger.info("Database update summary:")
    logger.info(f"  Processed {processed_repo_count} repositories")
    logger.info(f"  Libraries: {new_libs_count} added, {updated_libs_count} updated. Total: {len(libraries_db)}")
    logger.info(f"  Primitives: {new_primitives_count} new, {updated_primitives_count} updated")
    logger.info(f"  Final categorized primitives: {len(final_primitives)}")
    logger.info(f"  Final uncategorized primitives: {len(final_uncategorized)}")

    save_json(libraries_db, LIBRARIES_FILE)
    save_json(final_primitives, PRIMITIVES_FILE)
    save_json(final_uncategorized, UNCATEGORIZED_PRIMITIVES_FILE)
    logger.info("All database files saved.")
