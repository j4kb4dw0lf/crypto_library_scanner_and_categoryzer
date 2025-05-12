import sqlite3
import json
import os
from collections import defaultdict

OUTPUT_DIR = "output"
DB_FILE = os.path.join(OUTPUT_DIR, "crypto_primitives.db")

def db_connect(db_path=DB_FILE):
    if not os.path.exists(db_path):
        print(f"Error: Database file not found at {db_path}")
        print("Please run the database builder script first.")
        return None
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def dump_primitives_with_multiple_categories(db_path=DB_FILE):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT primitive_id
            FROM Primitive_Categories
            GROUP BY primitive_id
            HAVING COUNT(category_id) > 1
        ''')
        primitive_ids = [row[0] for row in cursor.fetchall()]

        if not primitive_ids:
            print("No primitives found with more than one category.")
            return

        placeholders = ','.join('?' for _ in primitive_ids)
        cursor.execute(f'''
            SELECT pc.primitive_id, p.name, pc.category_id, c.name
            FROM Primitive_Categories pc
            JOIN Primitives p ON pc.primitive_id = p.primitive_id
            JOIN Categories c ON pc.category_id = c.category_id
            WHERE pc.primitive_id IN ({placeholders})
            ORDER BY pc.primitive_id
        ''', primitive_ids)

        primitive_data = defaultdict(lambda: {"name": "", "categories": []})
        for primitive_id, primitive_name, category_id, category_name in cursor.fetchall():
            primitive_data[primitive_id]["name"] = primitive_name
            primitive_data[primitive_id]["categories"].append((category_id, category_name))

        print("Primitives with more than one category:")
        for primitive_id, info in primitive_data.items():
            print(f"- Primitive ID {primitive_id} | Name: {info['name']}")
            print("  Categories:")
            for category_id, category_name in info["categories"]:
                print(f"    - Category ID {category_id} | Name: {category_name}")

        cursor.close()
        conn.close()

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")

def get_all_libraries(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT library_id, name, version, source_url, last_updated FROM Libraries ORDER BY name, version")
    libraries = cursor.fetchall()
    return [dict(lib) for lib in libraries]

def get_primitives_by_library(conn, library_name: str, library_version: str = None):
    library_name = library_name.lower()
    cursor = conn.cursor()
    query = """
        SELECT p.primitive_id, p.name, p.parameters, p.return_type, p.comment_alternative, l.version as library_version
        FROM Primitives p
        JOIN Libraries l ON p.library_id = l.library_id
        WHERE l.name = ?
    """
    params = [library_name]
    if library_version:
        query += " AND l.version = ?"
        params.append(library_version)
    query += " ORDER BY p.name"
    
    cursor.execute(query, tuple(params))
    primitives_raw = cursor.fetchall()
    
    primitives_list = []
    for p_raw in primitives_raw:
        p_dict = dict(p_raw)
        try:
            p_dict['parameters'] = json.loads(p_dict['parameters'])
        except (json.JSONDecodeError, TypeError):
            p_dict['parameters'] = []
        
        cursor.execute("""
            SELECT c.name 
            FROM Categories c
            JOIN Primitive_Categories pc ON c.category_id = pc.category_id
            WHERE pc.primitive_id = ?
            ORDER BY c.name
        """, (p_dict['primitive_id'],))
        categories = [row[0] for row in cursor.fetchall()]
        p_dict['categories'] = categories
        primitives_list.append(p_dict)
        
    return primitives_list

def get_primitives_by_category(conn, category_name: str):
    category_name = category_name.lower()
    cursor = conn.cursor()
    cursor.execute("SELECT category_id FROM Categories WHERE name = ?", (category_name,))
    cat_row = cursor.fetchone()
    if not cat_row:
        print(f"Category '{category_name}' not found.")
        return []
    category_id = cat_row['category_id']

    query = """
        SELECT p.primitive_id, p.name, p.parameters, p.return_type, p.comment_alternative, 
               l.name as library_name, l.version as library_version
        FROM Primitives p
        JOIN Libraries l ON p.library_id = l.library_id
        JOIN Primitive_Categories pc ON p.primitive_id = pc.primitive_id
        WHERE pc.category_id = ?
        ORDER BY l.name, p.name
    """
    cursor.execute(query, (category_id,))
    primitives_raw = cursor.fetchall()

    primitives_list = []
    for p_raw in primitives_raw:
        p_dict = dict(p_raw)
        try:
            p_dict['parameters'] = json.loads(p_dict['parameters'])
        except (json.JSONDecodeError, TypeError):
            p_dict['parameters'] = []
        p_dict['categories'] = [category_name]
        primitives_list.append(p_dict)
        
    return primitives_list

def get_primitive_details(conn, primitive_name: str, library_name: str, library_version: str = None):
    library_name = library_name.lower()
    cursor = conn.cursor()
    query = """
        SELECT p.primitive_id, p.name, p.parameters, p.return_type, p.comment_alternative,
               l.name as library_name, l.version as library_version
        FROM Primitives p
        JOIN Libraries l ON p.library_id = l.library_id
        WHERE p.name = ? AND l.name = ?
    """
    params = [primitive_name, library_name]
    if library_version:
        query += " AND l.version = ?"
        params.append(library_version)
    
    cursor.execute(query, tuple(params))
    primitives_raw = cursor.fetchall()
    if not primitives_raw:
        print(f"Primitive '{primitive_name}' not found in library '{library_name}' (version: {library_version or 'any'}).")
        return None if library_version else []

    results = []
    for p_raw in primitives_raw:
        p_dict = dict(p_raw)
        try:
            p_dict['parameters'] = json.loads(p_dict['parameters'])
        except (json.JSONDecodeError, TypeError):
            p_dict['parameters'] = []

        cursor.execute("""
            SELECT c.name 
            FROM Categories c
            JOIN Primitive_Categories pc ON c.category_id = pc.category_id
            WHERE pc.primitive_id = ?
            ORDER BY c.name
        """, (p_dict['primitive_id'],))
        categories = [row[0] for row in cursor.fetchall()]
        p_dict['categories'] = categories
        results.append(p_dict)
    
    return results[0] if library_version and results else results

def search_primitives_by_name(conn, search_term: str):
    cursor = conn.cursor()
    query = """
        SELECT p.primitive_id, p.name, p.parameters, p.return_type, p.comment_alternative,
               l.name as library_name, l.version as library_version
        FROM Primitives p
        JOIN Libraries l ON p.library_id = l.library_id
        WHERE p.name LIKE ?
        ORDER BY l.name, p.name
    """
    cursor.execute(query, (f'%{search_term}%',))
    primitives_raw = cursor.fetchall()
    
    primitives_list = []
    for p_raw in primitives_raw:
        p_dict = dict(p_raw)
        try:
            p_dict['parameters'] = json.loads(p_dict['parameters'])
        except (json.JSONDecodeError, TypeError):
            p_dict['parameters'] = []
        
        cursor.execute("""
            SELECT c.name 
            FROM Categories c
            JOIN Primitive_Categories pc ON c.category_id = pc.category_id
            WHERE pc.primitive_id = ?
            ORDER BY c.name
        """, (p_dict['primitive_id'],))
        categories = [row[0] for row in cursor.fetchall()]
        p_dict['categories'] = categories
        primitives_list.append(p_dict)
        
    return primitives_list

def list_all_categories(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM Categories ORDER BY name")
    categories = cursor.fetchall()
    return [row['name'] for row in categories]

if __name__ == '__main__':
    conn = db_connect()
    if conn:
        print("--- All Libraries ---")
        all_libs = get_all_libraries(conn)
        for lib in all_libs:
            print(f"  ID: {lib['library_id']}, Name: {lib['name']}, Version: {lib['version']}, URL: {lib['source_url']}, Updated: {lib['last_updated']}")
        print("-" * 30, "\n")

        print("--- Primitives in OpenSSL (3.5.0) ---")
        openssl_prims = get_primitives_by_library(conn, library_name="OpenSSL", library_version="3.5.0")
        if openssl_prims:
            for p in openssl_prims:
                print(f"  Name: {p['name']}")
                print(f"    Params: {p['parameters']}")
                print(f"    Return: {p['return_type']}")
                print(f"    Categories: {p['categories']}")
                print(f"    Comment: {p['comment_alternative']}")
        else:
            print("  No primitives found for OpenSSL 3.5.0 (or library not in DB).")
        print("-" * 30, "\n")
        
        print("--- Primitives in OpenSSL (all versions) ---")
        all_openssl_prims = get_primitives_by_library(conn, library_name="OpenSSL")
        if all_openssl_prims:
             print(f"  Found {len(all_openssl_prims)} primitives for OpenSSL (all versions). First few:")
             for p in all_openssl_prims[:3]:
                print(f"  Name: {p['name']} (Version: {p['library_version']})")
                print(f"    Categories: {p['categories']}")
        else:
            print("  No primitives found for OpenSSL (or library not in DB).")

        print("-" * 30, "\n")

        print("--- Primitives with category 'sign' ---")
        sign_prims = get_primitives_by_category(conn, category_name="des")
        if sign_prims:
            for p in sign_prims:
                print(f"  Lib: {p['library_name']} {p['library_version']}, Name: {p['name']}, Categories: {p['categories']}")
        else:
            print("  No primitives found with category 'sign'.")
        print("-" * 30, "\n")

        print("--- Details for 'ossl_cipher_capable_aes_cbc_hmac_sha512_etm' in OpenSSL 3.5.0 ---")
        details = get_primitive_details(conn, primitive_name="ossl_cipher_capable_aes_cbc_hmac_sha512_etm", library_name="OpenSSL", library_version="3.5.0")
        if details:
            print(f"  Name: {details['name']}")
            print(f"    Params: {details['parameters']}")
            print(f"    Return: {details['return_type']}")
            print(f"    Categories: {details['categories']}")
            print(f"    Comment: {details['comment_alternative']}")
        print("-" * 30, "\n")

        print("--- Search primitives containing 'SHA512' ---")
        sha_prims = search_primitives_by_name(conn, search_term="SHA512")
        if sha_prims:
            for p in sha_prims:
                print(f"  Lib: {p['library_name']} {p['library_version']}, Name: {p['name']}")
        else:
            print("  No primitives found containing 'SHA512'.")
        print("-" * 30, "\n")

        print("--- All Categories ---")
        all_cats = list_all_categories(conn)
        print(f"  {all_cats}")
        print("-" * 30, "\n")

        conn.close()
    else:
        print("Failed to connect to the database.")
