import re
import json
import os

json_path = os.path.join(os.path.dirname(__file__), "cats_alts.json")
with open(json_path, "r", encoding="utf-8") as f:
    cts_data = json.load(f)

ALGOS = cts_data.get("ALGOS", {})
OPS =  cts_data.get("OPS", {})
ALTS = cts_data.get("ALTS", {})

def flatten_categorized_data(categorized_dict):
    flat_set = set()
    for _, sub_dict_or_list in categorized_dict.items():
        if isinstance(sub_dict_or_list, dict):
            flat_set.update(flatten_categorized_data(sub_dict_or_list))
        elif isinstance(sub_dict_or_list, list):
            for item in sub_dict_or_list:
                flat_set.add(item)
    return flat_set

ALL_ALGOS_FLAT = flatten_categorized_data(ALGOS)
ALL_OPS_FLAT = flatten_categorized_data(OPS)

LIB_CONFIG = {
    'openssl': {'prefixes': ['EVP_', 'evp_'], 'namespaces': []},
    'libsodium': {'prefixes': ['crypto_', 'sodium_'], 'namespaces': []},
    'libssh2': {'prefixes': ['libssh2_'], 'namespaces': []},
    'botan': {'prefixes': ['botan_'], 'namespaces': ['Botan', 'botan', 'botan::', 'Botan::']},
    'cryptopp': {'prefixes': [], 'namespaces': ['CryptoPP']},
    'wolfssl': {'prefixes': ['wolfSSL_', 'wolfssl_'], 'namespaces': []}
}

ALGO_TOKEN_TO_INFO = {}

def build_algo_token_info_map(data, path, info_map):
    """
    Recursively builds a map from an algorithm token to its full category path.
    FIXED: Stores the entire path as a tuple.
    """
    if isinstance(data, dict):
        for key, value in data.items():
            build_algo_token_info_map(value, path + [key], info_map)
    elif isinstance(data, list):
        # The path now contains all keys leading to the token list
        # e.g., ['PublicKeyCryptography', 'Encryption & Key Exchange', 'DH']
        for token in data:
            info_map.setdefault(token, set()).add(tuple(path))

build_algo_token_info_map(ALGOS, [], ALGO_TOKEN_TO_INFO)



OP_TOKEN_TO_MAIN_CLASSES = {}
for main_class, subcategories_dict in OPS.items():
    to_process_stack = [subcategories_dict]
    while to_process_stack:
        current_item = to_process_stack.pop()
        if isinstance(current_item, dict):
            for _key, value in current_item.items():
                if isinstance(value, list):
                    for op_token in value:
                        if isinstance(op_token, str):
                            OP_TOKEN_TO_MAIN_CLASSES.setdefault(op_token, set()).add(main_class)
                elif isinstance(value, dict):
                    to_process_stack.append(value)

def get_relevant_name_part(full_name: str, library: str) -> str:
    cfg = LIB_CONFIG.get(library.lower(), {})
    name_to_process = full_name
    namespaces = cfg.get('namespaces', [])
    if namespaces and '::' in name_to_process:
        for ns in namespaces:
            if name_to_process.startswith(ns + '::'):
                name_to_process = name_to_process[len(ns)+2:]
                break
    prefixes = sorted(cfg.get('prefixes', []), key=len, reverse=True)
    name_lower = name_to_process.lower()
    for p in prefixes:
        if name_lower.startswith(p.lower()):
            prefix_len = len(p)
            name_to_process = name_to_process[prefix_len:]
            break
    return name_to_process

def tokenize_and_recombine(name_part: str, known_tokens: set) -> list[str]:
    if not name_part:
        return []
    split_parts = re.split(r'[_::]+', name_part)
    raw_tokens = []
    for part in split_parts:
        if not part: continue
        matches = re.findall(r'[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+[0-9]*|[A-Z]+|[0-9]+', part)
        raw_tokens.extend(m for m in matches if m)
    lowercase_tokens = [t.lower() for t in raw_tokens if t]
    if not lowercase_tokens:
        return []
    recombined = []
    i = 0
    max_words_to_combine = 1
    if known_tokens:
        calculated_max_words = max((kt.count('_') + kt.count('-') + 1 for kt in known_tokens), default=1)
        max_words_to_combine = min(calculated_max_words, 4)
    while i < len(lowercase_tokens):
        found_match = False
        for length in range(min(max_words_to_combine, len(lowercase_tokens) - i), 0, -1):
            current_slice = lowercase_tokens[i : i + length]
            potential_combos = {
                "".join(current_slice),
                "-".join(current_slice),
                "_".join(current_slice)
            }
            for combo in potential_combos:
                if combo in known_tokens:
                    recombined.append(combo)
                    i += length
                    found_match = True
                    break
            if found_match:
                break
        if not found_match:
            recombined.append(lowercase_tokens[i])
            i += 1
    return recombined



def get_classification_details(name_part_str: str):
    """
    Analyzes a name part and returns its operation classes, algorithm classes, and keys for alt lookups.
    FIXED: Traverses ALTS using the full path for robust alternative finding.
    """
    tokens_for_ops = tokenize_and_recombine(name_part_str, ALL_OPS_FLAT)
    tokens_for_algos = tokenize_and_recombine(name_part_str, ALL_ALGOS_FLAT)

    # Get main OPS categories (this logic is unchanged)
    op_main_classes = set()
    for t_op in tokens_for_ops:
        op_main_classes.update(OP_TOKEN_TO_MAIN_CLASSES.get(t_op, set()))

    # Get main ALGOS categories and alternatives using the full path
    algo_main_classes = set()
    alternatives = set()
    for t_algo in tokens_for_algos:
        # ALGO_TOKEN_TO_INFO now contains a set of full paths for each token
        for path_tuple in ALGO_TOKEN_TO_INFO.get(t_algo, set()):
            # The main class is the first element in the path
            algo_main_classes.add(path_tuple[0])
            
            # Traverse the ALTS dictionary using the full path
            current_level_in_alts = ALTS
            try:
                for key in path_tuple:
                    current_level_in_alts = current_level_in_alts[key]
                
                # If we successfully traversed the path and found a string, it's an alternative
                if isinstance(current_level_in_alts, str):
                    alternatives.add(current_level_in_alts)
            except (KeyError, TypeError):
                # This path does not exist in the ALTS dictionary, so we skip it.
                continue

    return sorted(list(op_main_classes)), sorted(list(algo_main_classes)), sorted(list(alternatives))

def classify(func_name: str, group: str, library: str) -> str:
    ops_classes, algo_classes, alternatives = [], [], []
    name_part_f = get_relevant_name_part(func_name, library)
    ops_f, algo_classes_f, alts_f = get_classification_details(name_part_f)
    if ops_f or algo_classes_f:
        ops_classes, algo_classes, alternatives = ops_f, algo_classes_f, alts_f
    else:
        name_part_g = get_relevant_name_part(group, library)
        ops_g, algo_classes_g, alts_g = get_classification_details(name_part_g)
        if ops_g or algo_classes_g:
            ops_classes, algo_classes, alternatives = ops_g, algo_classes_g, alts_g
    if not ops_classes and not algo_classes:
        return 'uncategorized'
    category_parts = []
    if ops_classes:
        category_parts.append("_".join(ops_classes))
    if algo_classes:
        category_parts.append("_".join(algo_classes))
    result_str = "_".join(category_parts)
    if ops_classes and not algo_classes:
        result_str += "_OPERATION"
    if alternatives:
        alt_str = "_".join(alternatives)
        return f"{result_str}%{alt_str}"
    return result_str

def is_quantum_safe(func_name: str, group: str, library: str) -> bool:
    pqc_set = set()
    for main_cat in ["KEMs", "DigitalSignaturesPQC"]:
        for sub_cat in ALGOS.get(main_cat, {}).values():
            pqc_set.update(sub_cat)
    safe_algos_combined = pqc_set
    name_part_func = get_relevant_name_part(func_name, library)
    tokens_func = tokenize_and_recombine(name_part_func, safe_algos_combined)
    if any(token in safe_algos_combined for token in tokens_func):
        return True
    name_part_group = get_relevant_name_part(group, library)
    tokens_group = tokenize_and_recombine(name_part_group, safe_algos_combined)
    if any(token in safe_algos_combined for token in tokens_group):
        return True
    return False


func_name_1 = "_libssh2_dh_secret"
group_1 = "..."
library_1 = "libssh2"
classification_1 = classify(func_name_1, group_1, library_1)
print(f"Function: '{func_name_1}'\nClassification: {classification_1}\n")