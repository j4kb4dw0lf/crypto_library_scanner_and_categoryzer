import json
import os
import logging
import sqlite3
from datetime import datetime, timezone
from .category_matcher import classify, is_quantum_safe

logger = logging.getLogger(__name__)

OUTPUT_DIR = "output"
DB_FILE = os.path.join(OUTPUT_DIR, "crypto_primitives.db")
NON_PQ_COMMENT = "Consider modern, quantum-safe alternatives."

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
        FOREIGN KEY (library_id) REFERENCES Libraries (library_id)
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
    logger.info("Database schema ensured.")


def get_or_create_category_ids_db(conn, category_names_str: str) -> list[int] | None:
    if not category_names_str or category_names_str.lower() == "uncategorized":
        return None
    individual_category_names = [name for name in category_names_str.split('_') if name]
    if not individual_category_names:
        return None
    cursor = conn.cursor()
    ids_list = []
    for name in individual_category_names:
        cursor.execute("SELECT category_id FROM Categories WHERE name = ?", (name,))
        row = cursor.fetchone()
        if row:
            ids_list.append(row[0])
        else:
            try:
                cursor.execute("INSERT INTO Categories (name) VALUES (?)", (name,))
                conn.commit()
                ids_list.append(cursor.lastrowid)
            except sqlite3.IntegrityError:
                logger.warning(f"Integrity error trying to insert category '{name}', refetching.")
                cursor.execute("SELECT category_id FROM Categories WHERE name = ?", (name,))
                row = cursor.fetchone()
                if row: ids_list.append(row[0])
                else: logger.error(f"Could not get or create category_id for '{name}' after integrity error.")
    return sorted(list(set(ids_list))) if ids_list else None

def build_database_sqlite(repo_results: list[dict], external_results: list[dict]):
    global DB_FILE, NON_PQ_COMMENT
    logger.info(f"Building/Updating SQLite database: {DB_FILE}")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    setup_database(conn)
    cursor = conn.cursor()
    new_libs_count, updated_libs_count = 0, 0
    new_primitives_count, updated_primitives_count = 0, 0
    processed_repo_count = 0
    all_scan_results = [{'data': res, '_type': 'repo'} for res in repo_results] + \
                       [{'data': res, '_type': 'external'} for res in external_results]
    for item in all_scan_results:
        result_item = item['data']
        result_type = item['_type']
        processed_repo_count +=1
        library_name_from_scan = result_item.get('library_name')
        library_version_from_scan = result_item.get('library_version')
        functions_from_scan = result_item.get('functions', [])
        repo_name_from_scan = result_item.get('repo_name') if result_type == 'repo' else result_item.get('external_lib_name')
        repo_url_from_scan = result_item.get('repo_url') if result_type == 'repo' else result_item.get('external_lib_path')
        if not repo_name_from_scan or not library_name_from_scan:
            logger.warning(f"Skipping result for '{repo_name_from_scan}' due to missing critical fields.")
            continue
        logger.info(f"Processing Library: {library_name_from_scan} (Version: {library_version_from_scan or 'Unknown'}) from {repo_name_from_scan} ({len(functions_from_scan)} functions)")
        current_time_iso = datetime.now(timezone.utc).isoformat()
        current_library_id = None
        try:
            cursor.execute("SELECT library_id, source_url FROM Libraries WHERE name = ? AND version = ?",
                           (library_name_from_scan, library_version_from_scan))
            lib_row = cursor.fetchone()
            if lib_row:
                current_library_id = lib_row[0]
                db_source_url = lib_row[1]
                if db_source_url != repo_url_from_scan:
                    cursor.execute("UPDATE Libraries SET source_url = ?, last_updated = ? WHERE library_id = ?",
                                   (repo_url_from_scan, current_time_iso, current_library_id))
                    updated_libs_count += 1
                else:
                    cursor.execute("UPDATE Libraries SET last_updated = ? WHERE library_id = ?",
                                   (current_time_iso, current_library_id))
            else:
                cursor.execute("""
                    INSERT INTO Libraries (name, version, source_url, scan_date, last_updated)
                    VALUES (?, ?, ?, ?, ?)
                """, (library_name_from_scan, library_version_from_scan, repo_url_from_scan, current_time_iso, current_time_iso))
                current_library_id = cursor.lastrowid
                new_libs_count += 1
            conn.commit()
            for func_data in functions_from_scan:
                func_name = func_data.get('full_name')
                filepath = func_data.get('filepath')
                if not func_name or not filepath: continue
                if "::operator" in func_name or "operator" in func_name.lower(): continue
                params_list = func_data.get('parameters', [])
                if not isinstance(params_list, list): params_list = []
                params_json_str = json.dumps(params_list)
                return_type = func_data.get('return_type')
                header_filename_base = os.path.splitext(os.path.basename(filepath))[0]
                namespace_group = func_name.split("::")[0] if "::" in func_name else header_filename_base
                category_name_str = classify(func_name, namespace_group, library_name_from_scan)
                current_categories_ids = get_or_create_category_ids_db(conn, category_name_str)
                is_pq_safe_flag = is_quantum_safe(func_name, namespace_group, library_name_from_scan)
                primitive_comment = NON_PQ_COMMENT if not is_pq_safe_flag else ""
                cursor.execute("""
                    SELECT primitive_id, return_type, comment_alternative
                    FROM Primitives
                    WHERE name = ? AND library_id = ? AND parameters = ?
                """, (func_name, current_library_id, params_json_str))
                primitive_row = cursor.fetchone()
                current_primitive_id = None
                if primitive_row:
                    current_primitive_id = primitive_row[0]
                    db_return_type = primitive_row[1]
                    db_comment = primitive_row[2]
                    updated_needed = False
                    if db_return_type != return_type: updated_needed = True
                    if db_comment != primitive_comment: updated_needed = True
                    cursor.execute("SELECT category_id FROM Primitive_Categories WHERE primitive_id = ?", (current_primitive_id,))
                    db_category_ids = sorted([r[0] for r in cursor.fetchall()])
                    if current_categories_ids is None: current_categories_ids = []
                    if set(db_category_ids) != set(current_categories_ids):
                        updated_needed = True
                        cursor.execute("DELETE FROM Primitive_Categories WHERE primitive_id = ?", (current_primitive_id,))
                        if current_categories_ids:
                            for cat_id in current_categories_ids:
                                cursor.execute("INSERT INTO Primitive_Categories (primitive_id, category_id) VALUES (?, ?)",
                                               (current_primitive_id, cat_id))
                    if updated_needed:
                        cursor.execute("""
                            UPDATE Primitives SET return_type = ?, comment_alternative = ?
                            WHERE primitive_id = ?
                        """, (return_type, primitive_comment, current_primitive_id))
                        updated_primitives_count += 1
                else:
                    cursor.execute("""
                        INSERT INTO Primitives (name, library_id, parameters, return_type, comment_alternative)
                        VALUES (?, ?, ?, ?, ?)
                    """, (func_name, current_library_id, params_json_str, return_type, primitive_comment))
                    current_primitive_id = cursor.lastrowid
                    new_primitives_count += 1
                    if current_categories_ids:
                        for cat_id in current_categories_ids:
                            cursor.execute("INSERT INTO Primitive_Categories (primitive_id, category_id) VALUES (?, ?)",
                                           (current_primitive_id, cat_id))
                conn.commit()
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"SQLite error during processing of {library_name_from_scan}: {e}")
        except Exception as e:
            conn.rollback()
            logger.error(f"General error during processing of {library_name_from_scan}: {e}")
    cursor.execute("SELECT COUNT(*) FROM Libraries")
    total_libs_in_db = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM Primitives")
    total_primitives_in_db = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM Categories")
    total_categories_in_db = cursor.fetchone()[0]
    conn.close()
    logger.info("Database update summary (based on operations):")
    logger.info(f"  Processed {processed_repo_count} repository/external entries.")
    logger.info(f"  Libraries: {new_libs_count} added, {updated_libs_count} updated.")
    logger.info(f"  Primitives: {new_primitives_count} new, {updated_primitives_count} updated.")
    logger.info("Database state after update:")
    logger.info(f"  Total libraries in DB: {total_libs_in_db}")
    logger.info(f"  Total primitives in DB: {total_primitives_in_db}")
    logger.info(f"  Total categories in DB: {total_categories_in_db}")
    logger.info(f"SQLite database '{DB_FILE}' updated.")
