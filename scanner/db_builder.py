import json
import os
import logging
import sqlite3
from datetime import datetime, timezone
from .category_matcher import classify, is_quantum_safe

logger = logging.getLogger(__name__)
if not logger.hasHandlers():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

OUTPUT_DIR = "output"
DB_FILE = os.path.join(OUTPUT_DIR, "crypto_primitives.db")
NON_PQ_COMMENT = "Consider modern, quantum-safe alternatives."

UNCATEGORIZED_JSON = os.path.join(OUTPUT_DIR, "uncategorized_primitives.json")

def save_uncategorized_primitive(func_name, lib_name, filepath, params_list, return_type):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    entry = {
        "name": func_name,
        "library": lib_name,
        "filepath": filepath,
        "parameters": params_list,
        "return_type": return_type,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    try:
        if os.path.exists(UNCATEGORIZED_JSON):
            with open(UNCATEGORIZED_JSON, "r", encoding="utf-8") as f:
                existing = json.load(f)
        else:
            existing = []

        existing.append(entry)

        with open(UNCATEGORIZED_JSON, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)
        logger.info(f"Uncategorized primitive '{func_name}' saved locally.")
    except Exception as e:
        logger.error(f"Failed to write uncategorized primitive to file: {e}", exc_info=True)


def setup_database(conn):
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Libraries (
        library_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        version TEXT,
        source_url TEXT,
        scan_date TEXT NOT NULL,
        last_updated TEXT NOT NULL,
        UNIQUE (name, version)
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Categories (
        category_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Primitives (
        primitive_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        library_id INTEGER NOT NULL,
        parameters TEXT,
        return_type TEXT,
        comment_alternative TEXT,
        need_arg INT,
        FOREIGN KEY (library_id) REFERENCES Libraries (library_id) ON DELETE CASCADE
    )
    ''')
    cursor.execute('''
    CREATE INDEX IF NOT EXISTS idx_primitive_name_library ON Primitives (name, library_id);
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Primitive_Categories (
        primitive_id INTEGER NOT NULL,
        category_id INTEGER NOT NULL,
        PRIMARY KEY (primitive_id, category_id),
        FOREIGN KEY (primitive_id) REFERENCES Primitives (primitive_id) ON DELETE CASCADE,
        FOREIGN KEY (category_id) REFERENCES Categories (category_id) ON DELETE CASCADE
    )
    ''')
    conn.commit()
    logger.debug("Database schema ensured.")

def get_or_create_category_ids_db(conn, category_names_str: str) -> list[int]:
    if not category_names_str or category_names_str.lower() == "uncategorized":
        return []
    individual_category_names = [name for name in category_names_str.split('_') if name]
    if not individual_category_names:
        return []
    cursor = conn.cursor()
    ids_list = []
    new_categories_added_in_call = False
    for name in individual_category_names:
        cursor.execute("SELECT category_id FROM Categories WHERE name = ?", (name,))
        row = cursor.fetchone()
        if row:
            ids_list.append(row[0])
        else:
            try:
                cursor.execute("INSERT INTO Categories (name) VALUES (?)", (name,))
                new_id = cursor.lastrowid
                if new_id is not None:
                    ids_list.append(new_id)
                    new_categories_added_in_call = True
                else:
                    logger.error(f"Failed to get lastrowid for new category '{name}'. Refetching.")
                    cursor.execute("SELECT category_id FROM Categories WHERE name = ?", (name,))
                    refetched_row = cursor.fetchone()
                    if refetched_row:
                        ids_list.append(refetched_row[0])
                    else:
                        logger.error(f"Could not get or create category_id for '{name}' after failed lastrowid.")
            except sqlite3.IntegrityError:
                logger.warning(f"Integrity error trying to insert category '{name}', likely already inserted or duplicate in input. Refetching.")
                cursor.execute("SELECT category_id FROM Categories WHERE name = ?", (name,))
                row = cursor.fetchone()
                if row:
                    ids_list.append(row[0])
                else:
                    logger.error(f"Could not get category_id for '{name}' after integrity error and refetch.")
    if new_categories_added_in_call:
        conn.commit()
    return sorted(list(set(ids_list)))

def build_database_sqlite(repo_results: list[dict], external_results: list[dict]):
    global DB_FILE, NON_PQ_COMMENT
    logger.info(f"Starting database build/update: {DB_FILE}")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    setup_database(conn)
    cursor = conn.cursor()
    new_libs_count, updated_libs_metadata_count = 0, 0
    new_primitives_count, updated_primitives_count = 0, 0
    processed_scan_items_count = 0
    all_scan_results = [{'data': res, '_type': 'repo'} for res in repo_results] + \
                       [{'data': res, '_type': 'external'} for res in external_results]
    for item_index, item in enumerate(all_scan_results):
        result_item = item['data']
        result_type = item['_type']
        processed_scan_items_count += 1
        library_name_from_scan = result_item.get('library_name')
        library_version_from_scan = result_item.get('library_version')
        if result_type == 'repo':
            source_identifier = result_item.get('repo_name', 'Unknown Repository')
            source_url = result_item.get('repo_url')
        else:
            source_identifier = result_item.get('external_lib_name', 'Unknown External Library')
            source_url = result_item.get('external_lib_path')
        functions_from_scan = result_item.get('functions', [])
        if not library_name_from_scan:
            logger.warning(f"Skipping item {item_index+1} ('{source_identifier}') due to missing 'library_name'.")
            continue
        logger.info(f"Processing Item {item_index+1}/{len(all_scan_results)}: Library '{library_name_from_scan}' (Version: {library_version_from_scan or 'N/A'}) from {source_identifier} ({len(functions_from_scan)} functions)")
        current_time_iso = datetime.now(timezone.utc).isoformat()
        current_library_id = None
        try:
            cursor.execute("SELECT library_id, source_url, last_updated FROM Libraries WHERE name = ? AND version IS ?",
                           (library_name_from_scan, library_version_from_scan))
            lib_row = cursor.fetchone()
            if lib_row:
                current_library_id = lib_row[0]
                db_source_url = lib_row[1]
                db_last_updated = lib_row[2]
                lib_metadata_changed = False
                if db_source_url != source_url:
                    cursor.execute("UPDATE Libraries SET source_url = ?, last_updated = ? WHERE library_id = ?",
                                   (source_url, current_time_iso, current_library_id))
                    lib_metadata_changed = True
                elif db_last_updated != current_time_iso:
                     cursor.execute("UPDATE Libraries SET last_updated = ? WHERE library_id = ?",
                                   (current_time_iso, current_library_id))
                if lib_metadata_changed:
                    updated_libs_metadata_count +=1
            else:
                cursor.execute("""
                    INSERT INTO Libraries (name, version, source_url, scan_date, last_updated)
                    VALUES (?, ?, ?, ?, ?)
                """, (library_name_from_scan, library_version_from_scan, source_url, current_time_iso, current_time_iso))
                current_library_id = cursor.lastrowid
                if current_library_id is None:
                    logger.error(f"Failed to get library_id for new library: {library_name_from_scan}")
                    conn.rollback()
                    continue
                new_libs_count += 1
            for func_data in functions_from_scan:
                func_name = func_data.get('full_name')
                filepath = func_data.get('filepath')
                if not func_name:
                    logger.debug(f"Skipping function due to missing 'full_name' in {library_name_from_scan}: {func_data}")
                    continue
                last_part_of_name = func_name.split("::")[-1]
                if "operator" in last_part_of_name.lower() and not any(kw in func_name.lower() for kw in ['encrypt', 'decrypt', 'sign', 'hash']):
                    logger.debug(f"Skipping likely non-crypto operator function: {func_name} in {library_name_from_scan}")
                    continue
                params_list = func_data.get('parameters', [])
                if not isinstance(params_list, list): params_list = []
                params_json_str = json.dumps(sorted(params_list))
                return_type = func_data.get('return_type', '')
                namespace_group = func_name.split("::")[0] if "::" in func_name else \
                                  (os.path.splitext(os.path.basename(filepath))[0] if filepath else "unknown_group")
                category_name_str = classify(func_name, namespace_group, library_name_from_scan)
                if category_name_str.lower() == "uncategorized":
                    save_uncategorized_primitive(func_name, library_name_from_scan, filepath, params_list, return_type)
                    continue  # Skip DB insert
                need_arg_value = 1 if category_name_str.endswith("_OPERATION") else None
                if category_name_str.endswith("_OPERATION"):
                    category_name_str = category_name_str[:-len("_OPERATION")]
                current_categories_ids = get_or_create_category_ids_db(conn, category_name_str)
                is_pq_safe_flag = is_quantum_safe(func_name, namespace_group, library_name_from_scan)
                primitive_comment = NON_PQ_COMMENT if not is_pq_safe_flag else ""
                cursor.execute("""
                    SELECT primitive_id, return_type, comment_alternative, need_arg
                    FROM Primitives
                    WHERE name = ? AND library_id = ? AND parameters = ?
                """, (func_name, current_library_id, params_json_str))
                primitive_row = cursor.fetchone()
                primitive_fields_changed = False
                categories_changed = False
                if primitive_row:
                    current_primitive_id = primitive_row[0]
                    db_return_type = primitive_row[1]
                    db_comment = primitive_row[2]
                    db_need_arg = primitive_row[3]
                    update_payload_primitives = {}
                    if db_return_type != return_type:
                        update_payload_primitives['return_type'] = return_type
                    if db_comment != primitive_comment:
                        update_payload_primitives['comment_alternative'] = primitive_comment
                    if db_need_arg != need_arg_value:
                        update_payload_primitives['need_arg'] = need_arg_value
                    if update_payload_primitives:
                        primitive_fields_changed = True
                    cursor.execute("SELECT category_id FROM Primitive_Categories WHERE primitive_id = ?", (current_primitive_id,))
                    db_category_ids = sorted([r[0] for r in cursor.fetchall()])
                    if set(db_category_ids) != set(current_categories_ids):
                        categories_changed = True
                        cursor.execute("DELETE FROM Primitive_Categories WHERE primitive_id = ?", (current_primitive_id,))
                        if current_categories_ids:
                            for cat_id in current_categories_ids:
                                cursor.execute("INSERT OR IGNORE INTO Primitive_Categories (primitive_id, category_id) VALUES (?, ?)",
                                               (current_primitive_id, cat_id))
                    if primitive_fields_changed:
                        set_clauses = [f"{key} = ?" for key in update_payload_primitives.keys()]
                        params_for_update = list(update_payload_primitives.values())
                        params_for_update.append(current_primitive_id)
                        sql_update_primitive = f"UPDATE Primitives SET {', '.join(set_clauses)} WHERE primitive_id = ?"
                        cursor.execute(sql_update_primitive, tuple(params_for_update))
                    if primitive_fields_changed or categories_changed:
                        updated_primitives_count += 1
                else:
                    cursor.execute("""
                        INSERT INTO Primitives (name, library_id, parameters, return_type, comment_alternative, need_arg)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (func_name, current_library_id, params_json_str, return_type, primitive_comment, need_arg_value))
                    current_primitive_id = cursor.lastrowid
                    if current_primitive_id is None:
                        logger.error(f"Failed to get primitive_id for new primitive: {func_name} in {library_name_from_scan}")
                        continue
                    new_primitives_count += 1
                    if current_categories_ids:
                        for cat_id in current_categories_ids:
                            cursor.execute("INSERT OR IGNORE INTO Primitive_Categories (primitive_id, category_id) VALUES (?, ?)",
                                           (current_primitive_id, cat_id))
            conn.commit()
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"SQLite error during processing of library {library_name_from_scan} (Source: {source_identifier}): {e}")
        except Exception as e:
            conn.rollback()
            logger.error(f"General error during processing of library {library_name_from_scan} (Source: {source_identifier}): {e}", exc_info=True)
    try:
        cursor.execute("SELECT COUNT(*) FROM Libraries")
        total_libs_in_db = cursor.fetchone()[0] if cursor.rowcount > -1 else -1
        cursor.execute("SELECT COUNT(*) FROM Primitives")
        total_primitives_in_db = cursor.fetchone()[0] if cursor.rowcount > -1 else -1
        cursor.execute("SELECT COUNT(*) FROM Categories")
        total_categories_in_db = cursor.fetchone()[0] if cursor.rowcount > -1 else -1
    except sqlite3.Error as e:
        logger.error(f"Error fetching final DB counts: {e}")
        total_libs_in_db, total_primitives_in_db, total_categories_in_db = -1, -1, -1
    conn.close()
    logger.info("--- Database Update Summary ---")
    logger.info(f"  Processed {processed_scan_items_count} scan entries.")
    logger.info(f"  Libraries: {new_libs_count} added, {updated_libs_metadata_count} had metadata updates (e.g. source URL, last_seen).")
    logger.info(f"  Primitives: {new_primitives_count} added, {updated_primitives_count} updated (fields or categories).")
    logger.info("--- Database State After Update ---")
    logger.info(f"  Total libraries in DB: {total_libs_in_db}")
    logger.info(f"  Total primitives in DB: {total_primitives_in_db}")
    logger.info(f"  Total categories in DB: {total_categories_in_db}")
    logger.info(f"SQLite database '{DB_FILE}' processing complete.")
