import re

ALGOS = {
    # Symmetric ciphers & modes
    'aes', 'des', '3des', 'tdes', 'camellia', 'aria', 'sm4', 'chacha',
    'chacha20', 'chacha20poly1305', 'salsa20', 'blowfish', 'twofish', 'serpent',
    'cast', 'rc4', 'rc5', 'rc6', 'idea', 'seed', 'gcm', 'ccm', 'eax',
    'hc128', 'hc256', 'rabbit', 'sosemanuk', 'xsalsa20', 'mars', 'rc2',
    'ecies', 'ed25519', 'curve25519', 'x25519', 'poly1305', 'xchacha20',
    # Hash functions
    'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3_224', 'sha3_256', 'hmacsha512256', 'hmacsha512','hmacsha256',
    'sha3_384', 'sha3_512', 'md2', 'md4', 'md5', 'blake2b', 'blake2s', 'blake3',
    'sm3', 'ripemd160', 'ripemd', 'whirlpool', 'tiger', 'keccak', 'shake128', 'shake256',
    # Asymmetric & PQC
    'rsa', 'dsa', 'ecdsa', 'eddsa', 'ed448', 'sm2',
    'crystals-kyber', 'kyber', 'crystals-dilithium', 'dilithium',
    'falcon', 'sphincs+', 'xmss', 'lms', 'picnic', 'newhope', 'frodokem', 'sike', 'sidh',
}
OPS = {
    'view', 'encrypt', 'decrypt', 'sign', 'verify', 'hash', 'hmac',
    'init', 'init_ex', 'update', 'final', 'cleanup', 'free', 'auth'
    'new', 'create', 'destroy', 'generate', 'derive', 'derivekey',
    'keygen', 'load', 'save', 'read', 'write', 'open', 'close', 'pubkey', 'privkey', 'pwdhash',
    'compute', 'seal', 'open', 'box', 'secretbox', 'pwhash', 'aead' 'keypair',
    'randombytes', 'get', 'set', 'seed', 'reseed', 'wrap', 'unwrap',
    'pad', 'unpad', 'mac', 'authenticate', 'derivebits',
}

LIB_CONFIG = {
    'openssl': {
        'prefixes': [
            'EVP_', 'evp_'],
        'namespaces': []
    },
    'libsodium': {
        'prefixes': ['crypto_', 'sodium_'],
        'namespaces': []
    },
    'libssh2': {
        'prefixes': ['libssh2_'],
        'namespaces': []
    },
    'botan': {
        'prefixes': ['botan_'],
        'namespaces': ['Botan']
    },
    'cryptopp': {
        'prefixes': [],
        'namespaces': ['CryptoPP']
    },
    'wolfssl': {
        'prefixes': ['wolfSSL_', 'wolfssl_'],
        'namespaces': []
    }
    # Add more library-specific configurations as needed
}

PQC_ALGOS = {
    'kyber', 'crystals-kyber', 'dilithium', 'crystals-dilithium',
    'falcon', 'sphincs+', 'xmss', 'lms', 'picnic', 'newhope', 'frodokem'
}
HEURISTIC_SAFE = {
    # Generally considered strong hash functions
    'blake3', 'sha3_256', 'sha3_384', 'sha3_512', 'shake128', 'shake256',
    # Modern ECC curves resistant to current non-quantum attacks
    'ed25519', 'ed448', 'curve25519', 'x25519'
}

# Combined set for quick checking in is_quantum_safe
SAFE_ALGOS_COMBINED = PQC_ALGOS | HEURISTIC_SAFE


def get_relevant_name_part(full_name: str, library: str) -> str:
    """Strips known library namespaces and prefixes from the name for better tokenization."""

    # Use library name (lowercase) to find config, default to empty if not found
    cfg = LIB_CONFIG.get(library.lower(), {})
    name_to_process = full_name

    # Strip C++ namespaces first (e.g., "Botan::")
    namespaces = cfg.get('namespaces', [])
    if namespaces and '::' in name_to_process:
        for ns in namespaces:
             if name_to_process.startswith(ns + '::'):
                  name_to_process = name_to_process[len(ns)+2:]
                  break # Assume only one top-level namespace to strip

    # Strip known prefixes (e.g., "EVP_")
    # Sort prefixes by length descending to match longer ones first (e.g., "wolfSSL_" before "wolf")
    prefixes = sorted(cfg.get('prefixes', []), key=len, reverse=True)
    name_lower = name_to_process.lower() # Compare lowercase for case-insensitivity
    for p in prefixes:
        if name_lower.startswith(p.lower()):
            prefix_len = len(p)
            name_to_process = name_to_process[prefix_len:]
            break # Assume only one prefix needs stripping

    return name_to_process

def tokenize_and_recombine(name_part: str, known_algos: set) -> list[str]:
    """
    Tokenizes the name part using regex splitting by common separators (_::)
    and camelCase/PascalCase conventions. Then attempts to recombine
    adjacent tokens that form known algorithm names from the provided set.
    Returns a list of lowercase tokens/recombined algorithm names.
    """
    if not name_part:
        return []

    # Split by underscore or double colon first
    split_parts = re.split(r'[_::]+', name_part)
    raw_tokens = []
    for part in split_parts:
        if not part: continue
        # Further split based on camelCase/PascalCase and digits
        # [A-Z]+(?=[A-Z][a-z]) -> Acronyms followed by PascalCase (e.g., HMACSha)
        # |[A-Z]?[a-z]+[0-9]* -> Optional uppercase followed by lowercase and optional digits (e.g., sha256, Aes, Ctr128)
        # |[A-Z]+ -> All uppercase acronyms (e.g., RSA, AES)
        # |[0-9]+ -> Digits (e.g., 256, 128)
        matches = re.findall(r'[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+[0-9]*|[A-Z]+|[0-9]+', part)
        raw_tokens.extend(m for m in matches if m) # Filter out empty strings

    lowercase_tokens = [t.lower() for t in raw_tokens if t]

    if not lowercase_tokens:
        return []

    recombined = []
    i = 0

    # Determine max words to check for recombination based on known algos
    # e.g., 'crystals-kyber' is 2 words, 'chacha20poly1305' could be 2 or 3 depending on base tokenization
    max_words = 1
    if known_algos:
       # Count separators ('-' or '_') + 1 for word count
       max_words = max((a.count('_') + a.count('-') + 1 for a in known_algos), default=1)
       # Limit lookahead to avoid excessive checks (e.g., max 3-4 words)
       max_words = min(max_words, 4)


    while i < len(lowercase_tokens):
        found_match = False
        # Try matching longest possible combinations first (down to single token)
        for length in range(min(max_words, len(lowercase_tokens) - i), 0, -1):
             # Try joining tokens directly and with hyphens/underscores if the known algo contains them
             potential_combo_direct = "".join(lowercase_tokens[i : i + length])
             potential_combo_hyphen = "-".join(lowercase_tokens[i : i + length])
             potential_combo_under = "_".join(lowercase_tokens[i : i + length])

             # Check against known algos set
             if potential_combo_direct in known_algos:
                 recombined.append(potential_combo_direct)
                 i += length
                 found_match = True
                 break
             elif potential_combo_hyphen in known_algos:
                  recombined.append(potential_combo_hyphen)
                  i += length
                  found_match = True
                  break
             elif potential_combo_under in known_algos:
                  recombined.append(potential_combo_under)
                  i += length
                  found_match = True
                  break

        if not found_match:
            # If no multi-token combo matched, add the single token and move on
            recombined.append(lowercase_tokens[i])
            i += 1

    return recombined



def classify(func_name: str, group: str, library: str) -> str:
    """
    Classifies the function based on tokens found in its 'relevant name part' or group name.
    Prioritizes matches from the function name over the group name.
    Returns a category string (e.g., "encrypt_aes") or "uncategorized".
    """

    # 1. Analyze Function Name
    name_part_func = get_relevant_name_part(func_name, library)
    tokens_func = tokenize_and_recombine(name_part_func, ALGOS)

    # Find unique algorithms and operations in the function name tokens
    algs_func = sorted(list(set(t for t in tokens_func if t in ALGOS)))
    ops_func = sorted(list(set(t for t in tokens_func if t in OPS)))

    category_parts = []
    # Prioritize operation then algorithm for category naming if both found
    if ops_func:
        category_parts.append("_".join(ops_func))
    if algs_func:
        category_parts.append("_".join(algs_func))

    if category_parts:
        return "_".join(category_parts) # Return combined classification from function name

    # 2. Analyze Group Name (if function name didn't yield category)
    # The 'group' is typically the base filename where the function was found
    name_part_group = get_relevant_name_part(group, library) # Apply same stripping logic
    tokens_group = tokenize_and_recombine(name_part_group, ALGOS)

    algs_group = sorted(list(set(t for t in tokens_group if t in ALGOS)))
    ops_group = sorted(list(set(t for t in tokens_group if t in OPS)))

    category_parts_group = []
    if ops_group:
        category_parts_group.append("_".join(ops_group))
    if algs_group:
        category_parts_group.append("_".join(algs_group))

    if category_parts_group:
        return "_".join(category_parts_group) # Return combined classification from group name

    # 3. Default
    return 'uncategorized'


def is_quantum_safe(func_name: str, group: str, library: str) -> bool:
    """
    Checks if the function name or group name contains tokens suggesting
    a known PQC algorithm or a heuristically safe modern algorithm.
    """
    # Use the combined set of explicitly PQC algos and heuristically safe ones
    relevant_safe_algos = SAFE_ALGOS_COMBINED

    # Check function name first
    name_part_func = get_relevant_name_part(func_name, library)
    tokens_func = tokenize_and_recombine(name_part_func, relevant_safe_algos)

    for token in tokens_func:
        if token in relevant_safe_algos:
            return True # Found safe algo token in function name

    # Check group name if not found in function name
    name_part_group = get_relevant_name_part(group, library)
    tokens_group = tokenize_and_recombine(name_part_group, relevant_safe_algos)

    for token in tokens_group:
        if token in relevant_safe_algos:
            return True # Found safe algo token in group name

    # If no safe tokens found in either name or group
    return False
