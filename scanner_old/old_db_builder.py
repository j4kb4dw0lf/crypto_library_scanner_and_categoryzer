import json
import os
import logging
from datetime import datetime, timezone
from operator import itemgetter
# Assuming category_matcher.py is in the same directory or accessible in PYTHONPATH
from .category_matcher import classify, is_quantum_safe

logger = logging.getLogger(__name__)

OUTPUT_DIR = "output"
PRIMITIVES_FILE = os.path.join(OUTPUT_DIR, "primitives.json")
UNCATEGORIZED_PRIMITIVES_FILE = os.path.join(OUTPUT_DIR, "uncategorized_primitives.json")
LIBRARIES_FILE = os.path.join(OUTPUT_DIR, "libraries.json")
CATEGORIES_FILE = os.path.join(OUTPUT_DIR, "categories.json")

# Default comment for primitives that are not quantum-safe
NON_PQ_COMMENT = "Consider modern, quantum-safe alternatives."

def load_json(filepath: str) -> list | dict:
    """Loads JSON data from a file."""
    if not os.path.exists(filepath):
        logger.warning(f"File not found: {filepath}. Returning empty list/dict as appropriate.")
        if filepath.endswith("primitives.json") or filepath.endswith("libraries.json") or filepath.endswith("categories.json"):
            return []
        return {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if filepath.endswith("primitives.json") or filepath.endswith("libraries.json") or filepath.endswith("categories.json"):
                if not isinstance(data, list):
                    logger.warning(f"Data in {filepath} is not a list as expected. Reinitializing as empty list.")
                    return []
            return data
    except (json.JSONDecodeError, IOError, Exception) as e:
        logger.error(f"Error loading JSON from {filepath}: {e}. Returning empty list/dict.")
        if filepath.endswith("primitives.json") or filepath.endswith("libraries.json") or filepath.endswith("categories.json"):
            return []
        return {}
    return []


def save_json(data: list | dict, filepath: str):
    """Saves data to a JSON file."""
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.debug(f"Successfully saved data to {filepath}")
    except (IOError, TypeError, Exception) as e:
        logger.error(f"Error saving JSON to {filepath}: {e}")

def get_or_create_category_ids(category_names_str: str,
                               categories_map: dict,
                               next_cat_id_list_ref: list) -> list[int] | None:
    """
    Gets or creates category IDs for a (potentially underscore-separated) string of category names.
    Individual category components are split by underscores.
    If new, categories are added to the map and IDs assigned.
    Returns a sorted list of unique category IDs, or None for 'uncategorized' or empty names.
    `next_cat_id_list_ref` is a list containing the next available ID (passed by reference).
    """
    if not category_names_str or category_names_str.lower() == "uncategorized":
        return None

    individual_category_names = [name for name in category_names_str.split('_') if name]
    
    if not individual_category_names:
        return None

    ids_list = []
    for name in individual_category_names:
        if name not in categories_map:
            cat_id = next_cat_id_list_ref[0]
            categories_map[name] = cat_id
            next_cat_id_list_ref[0] += 1
        ids_list.append(categories_map[name])
    
    return sorted(list(set(ids_list))) if ids_list else None


def build_database(repo_results: list[dict], external_results: list[dict]):
    """
    Builds or updates the JSON database files for cryptographic primitives,
    libraries, and categories. Comments are now in primitives, and is_post_quantum_safe is removed.
    """
    global PRIMITIVES_FILE, UNCATEGORIZED_PRIMITIVES_FILE, LIBRARIES_FILE, CATEGORIES_FILE, NON_PQ_COMMENT
    logger.info(f"Building/Updating JSON database files in '{OUTPUT_DIR}' directory.")

    # 1. Load Categories or initialize
    categories_map = {}
    next_category_id_val = 1
    if os.path.exists(CATEGORIES_FILE):
        loaded_categories = load_json(CATEGORIES_FILE)
        if isinstance(loaded_categories, list):
            for cat_entry in loaded_categories:
                if isinstance(cat_entry, dict) and 'name' in cat_entry and 'category_id' in cat_entry:
                    categories_map[cat_entry['name']] = cat_entry['category_id']
                    next_category_id_val = max(next_category_id_val, cat_entry['category_id'] + 1)
        else:
            logger.warning(f"{CATEGORIES_FILE} did not load as a list. Initializing categories anew.")
    next_category_id_ref = [next_category_id_val]

    # 2. Load Libraries
    libraries_db = load_json(LIBRARIES_FILE)
    if not isinstance(libraries_db, list): libraries_db = []
    existing_libs_map = {(lib.get('name'), lib.get('version')): index for index, lib in enumerate(libraries_db)}
    lib_id_counter = max([lib.get('library_id', 0) for lib in libraries_db if isinstance(lib, dict)] + [0]) + 1

    # 3. Load and Adapt Existing Primitives from files
    raw_primitives_from_file = load_json(PRIMITIVES_FILE)
    if not isinstance(raw_primitives_from_file, list): raw_primitives_from_file = []
    raw_uncategorized_from_file = load_json(UNCATEGORIZED_PRIMITIVES_FILE)
    if not isinstance(raw_uncategorized_from_file, list): raw_uncategorized_from_file = []
    
    lib_name_version_to_id_map = {
        (lib.get('name'), lib.get('version')): lib.get('library_id')
        for lib in libraries_db if isinstance(lib, dict) and lib.get('name') and lib.get('library_id') is not None
    }

    existing_primitives_store = {}
    current_max_primitive_id = 0

    for p_old_list in [raw_primitives_from_file, raw_uncategorized_from_file]:
        for p_old in p_old_list:
            if not isinstance(p_old, dict): continue

            p_id = p_old.get('id')
            if p_id is None:
                logger.warning(f"Primitive missing ID: {p_old.get('name')}. Skipping.")
                continue
            current_max_primitive_id = max(current_max_primitive_id, p_id)

            lib_name_for_key = p_old.get('library')
            func_name_for_key = p_old.get('name')
            params_for_key = tuple(p_old.get('parameters', []))

            if not func_name_for_key:
                logger.warning(f"Old primitive missing function name. ID: {p_id}. Skipping.")
                continue
            
            if not lib_name_for_key:
                old_lib_id = p_old.get('library_id')
                if old_lib_id is not None:
                    for lib_entry in libraries_db:
                        if lib_entry.get('library_id') == old_lib_id:
                            lib_name_for_key = lib_entry.get('name')
                            break
                if not lib_name_for_key:
                    logger.warning(f"Old primitive (ID: {p_id}, Name: {func_name_for_key}) missing library name and unresolvable library_id. Skipping.")
                    continue

            # Determine comment based on old is_post_quantum_safe or existing comment
            primitive_comment = p_old.get('comment/alternative', "") # Default to empty if not present
            if 'is_post_quantum_safe' in p_old and not p_old['is_post_quantum_safe'] and not primitive_comment:
                primitive_comment = NON_PQ_COMMENT
            
            adapted_p = {
                "id": p_id,
                "name": func_name_for_key,
                "parameters": p_old.get('parameters', []),
                "return_type": p_old.get('return_type'),
                "comment/alternative": primitive_comment
            }

            if 'library_id' in p_old and isinstance(p_old['library_id'], int):
                adapted_p['library_id'] = p_old['library_id']
            else:
                lib_version_old = p_old.get('library_version_found_in')
                adapted_p['library_id'] = lib_name_version_to_id_map.get((lib_name_for_key, lib_version_old))
                if adapted_p['library_id'] is None:
                     adapted_p['library_id'] = next(
                         (lib.get('library_id') for lib in libraries_db
                          if isinstance(lib, dict) and lib.get('name') == lib_name_for_key), None
                     )
            
            if 'categories_id' in p_old and isinstance(p_old['categories_id'], list):
                adapted_p['categories_id'] = sorted(list(set(p_old['categories_id'])))
            elif 'category' in p_old:
                cat_name_str = p_old['category']
                adapted_p['categories_id'] = get_or_create_category_ids(
                    cat_name_str, categories_map, next_category_id_ref
                )
            else:
                adapted_p['categories_id'] = None
            
            primitive_lookup_key = (lib_name_for_key, func_name_for_key, params_for_key)
            existing_primitives_store[primitive_lookup_key] = adapted_p
            
    primitive_id_counter = current_max_primitive_id + 1

    # 4. Process new scan results
    processed_primitives_in_current_run = {} 
    processed_primitive_keys_this_run = set()
    new_libs_count, updated_libs_count = 0, 0
    new_primitives_count, updated_primitives_count = 0, 0
    processed_repo_count = 0

    all_scan_results = [{'data': res, '_type': 'repo'} for res in repo_results] + \
                       [{'data': res, '_type': 'external'} for res in external_results]

    for item in all_scan_results:
        result_item = item['data']
        result_type = item['_type']
        processed_repo_count +=1
        
        library_name = result_item.get('library_name')
        library_version = result_item.get('library_version')
        functions = result_item.get('functions', [])
        
        repo_name = result_item.get('repo_name') if result_type == 'repo' else result_item.get('external_lib_name')
        repo_url = result_item.get('repo_url') if result_type == 'repo' else result_item.get('external_lib_path')

        if not repo_name or not library_name:
            logger.warning(f"Skipping result for '{repo_name}' due to missing critical fields.")
            continue
        
        logger.info(f"Processing: {library_name} (Version: {library_version or 'Unknown'}) from {repo_name}")

        lib_key_tuple = (library_name, library_version)
        current_time_iso = datetime.now(timezone.utc).isoformat()
        current_library_id = None

        if lib_key_tuple in existing_libs_map:
            lib_index = existing_libs_map[lib_key_tuple]
            current_lib_entry = libraries_db[lib_index]
            update_occurred = False
            if current_lib_entry.get('source_url') != repo_url:
                current_lib_entry['source_url'] = repo_url
                update_occurred = True
            current_lib_entry['last_updated'] = current_time_iso
            if update_occurred: updated_libs_count += 1
            current_library_id = current_lib_entry['library_id']
        else:
            current_library_id = lib_id_counter
            new_lib_entry = {
                "library_id": current_library_id, "name": library_name, "version": library_version,
                "source_url": repo_url, "scan_date": current_time_iso, "last_updated": current_time_iso,
            }
            libraries_db.append(new_lib_entry)
            existing_libs_map[lib_key_tuple] = len(libraries_db) - 1
            lib_name_version_to_id_map[(library_name, library_version)] = current_library_id
            lib_id_counter += 1
            new_libs_count += 1
        
        for func_data in functions:
            func_name = func_data.get('full_name')
            filepath = func_data.get('filepath')

            if not func_name or not filepath: continue
            if "::operator" in func_name or "operator" in func_name.lower(): continue

            params_list = func_data.get('parameters', [])
            if not isinstance(params_list, list): params_list = []
            params_tuple = tuple(params_list)
            
            primitive_lookup_key = (library_name, func_name, params_tuple)
            processed_primitive_keys_this_run.add(primitive_lookup_key)

            header_filename_base = os.path.splitext(os.path.basename(filepath))[0]
            namespace_group = func_name.split("::")[0] if "::" in func_name else header_filename_base
            
            category_name_str = classify(func_name, namespace_group, library_name)
            current_categories_ids = get_or_create_category_ids(
                category_name_str, categories_map, next_category_id_ref
            )
            
            # Determine comment based on quantum safety
            is_pq_safe_flag = is_quantum_safe(func_name, namespace_group, library_name)
            primitive_comment_for_new_entry = ""
            if not is_pq_safe_flag:
                primitive_comment_for_new_entry = NON_PQ_COMMENT


            existing_primitive_from_file = existing_primitives_store.get(primitive_lookup_key)
            
            primitive_entry_data = {
                "id": existing_primitive_from_file['id'] if existing_primitive_from_file else primitive_id_counter,
                "name": func_name,
                "library_id": current_library_id,
                "categories_id": current_categories_ids,
                "parameters": params_list,
                "return_type": func_data.get('return_type'),
                "comment/alternative": primitive_comment_for_new_entry # Set based on is_pq_safe_flag
            }

            if existing_primitive_from_file:
                existing_cat_ids = set(existing_primitive_from_file.get('categories_id') or [])
                new_cat_ids = set(primitive_entry_data.get('categories_id') or [])

                # If the existing primitive already had a more specific comment, preserve it
                # unless the new scan explicitly makes it non-PQ and it had no comment.
                if existing_primitive_from_file.get("comment/alternative") and not primitive_comment_for_new_entry:
                    primitive_entry_data["comment/alternative"] = existing_primitive_from_file.get("comment/alternative")
                elif existing_primitive_from_file.get("comment/alternative") and primitive_comment_for_new_entry == NON_PQ_COMMENT and existing_primitive_from_file.get("comment/alternative") != NON_PQ_COMMENT:
                     # If existing comment is more specific than the generic NON_PQ_COMMENT, keep it.
                     primitive_entry_data["comment/alternative"] = existing_primitive_from_file.get("comment/alternative")


                changed_fields = (
                    existing_primitive_from_file.get('library_id') != primitive_entry_data['library_id'] or
                    existing_cat_ids != new_cat_ids or
                    existing_primitive_from_file.get('comment/alternative', "") != primitive_entry_data.get('comment/alternative', "") or # Compare comments
                    tuple(existing_primitive_from_file.get('parameters',[])) != tuple(primitive_entry_data['parameters']) or
                    existing_primitive_from_file.get('return_type') != primitive_entry_data['return_type']
                )
                if changed_fields:
                    processed_primitives_in_current_run[primitive_lookup_key] = primitive_entry_data
                    updated_primitives_count += 1
                else:
                    processed_primitives_in_current_run[primitive_lookup_key] = existing_primitive_from_file
            else:
                processed_primitives_in_current_run[primitive_lookup_key] = primitive_entry_data
                primitive_id_counter += 1
                new_primitives_count += 1

    # 5. Consolidate all primitives for final output
    final_categorized_primitives, final_uncategorized_primitives = [], []

    for _, p_data in processed_primitives_in_current_run.items():
        if p_data.get("categories_id") is None:
            final_uncategorized_primitives.append(p_data)
        else:
            final_categorized_primitives.append(p_data)
    
    for key, existing_p_data in existing_primitives_store.items():
        if key not in processed_primitive_keys_this_run:
            if existing_p_data.get("categories_id") is None:
                final_uncategorized_primitives.append(existing_p_data)
            else:
                final_categorized_primitives.append(existing_p_data)
    
    lib_id_to_name_map = {
        lib.get('library_id'): lib.get('name') 
        for lib in libraries_db if isinstance(lib, dict) and lib.get('library_id') is not None
    }
    def sort_key_for_primitives(p_entry):
        lib_name = lib_id_to_name_map.get(p_entry.get('library_id'), '')
        return (lib_name, p_entry.get('name', ''))

    final_categorized_primitives.sort(key=sort_key_for_primitives)
    final_uncategorized_primitives.sort(key=sort_key_for_primitives)

    # 6. Prepare Categories JSON data (now only id and name)
    final_categories_list_for_json = [
        {"category_id": cat_id, "name": cat_name} # Removed "comment/alternative"
        for cat_name, cat_id in categories_map.items()
    ]
    final_categories_list_for_json.sort(key=itemgetter('category_id'))

    # 7. Save all database files
    save_json(libraries_db, LIBRARIES_FILE)
    save_json(final_categorized_primitives, PRIMITIVES_FILE)
    save_json(final_uncategorized_primitives, UNCATEGORIZED_PRIMITIVES_FILE)
    save_json(final_categories_list_for_json, CATEGORIES_FILE)

    logger.info("Database update summary:")
    logger.info(f"  Processed {processed_repo_count} repository/external entries.")
    logger.info(f"  Libraries: {new_libs_count} added, {updated_libs_count} updated. Total: {len(libraries_db)}")
    logger.info(f"  Primitives: {new_primitives_count} new, {updated_primitives_count} updated. ")
    logger.info(f"  Total categorized primitives: {len(final_categorized_primitives)}")
    logger.info(f"  Total uncategorized primitives: {len(final_uncategorized_primitives)}")
    logger.info(f"  Total atomic categories in DB: {len(final_categories_list_for_json)}")
    logger.info("All database files saved.")