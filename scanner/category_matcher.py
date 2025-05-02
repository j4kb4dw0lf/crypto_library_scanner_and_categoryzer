import re

ALGOS = {
    'aes', 'aes128', 'aes192', 'aes256', 'des', '3des', 'tdes', 'camellia', 'aria', 'sm4', 'chacha',
    'chacha20', 'chacha20poly1305', 'salsa20', 'blowfish', 'twofish', 'serpent', 'cast', 'rc4', 'rc5',
    'rc6', 'idea', 'seed', 'gcm', 'ccm', 'eax', 'hc128', 'hc256', 'rabbit', 'sosemanuk', 'xsalsa20',
    'mars', 'rc2', 'ecies', 'ed25519', 'curve25519', 'x25519', 'poly1305', 'xchacha20', 'ocb', 'ctr',
    'cbc', 'cfb', 'ofb', 'xts', 'cmac', 'pmac',
    'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512',
    'hmacsha512256', 'hmacsha512', 'hmacsha256', 'md2', 'md4', 'md5', 'blake2b', 'blake2s', 'blake3',
    'sm3', 'ripemd160', 'ripemd', 'whirlpool', 'tiger', 'keccak', 'shake128', 'shake256', 'streebog',
    'gosthash', 'sha512_224', 'sha512_256',
    'rsa', 'dsa', 'ecdsa', 'eddsa', 'ed448', 'sm2', 'dh', 'ecdh', 'ecdsap256', 'ecdsap384', 'ecdsap521',
    'crystals-kyber', 'kyber', 'crystals-dilithium', 'dilithium', 'falcon', 'sphincs+', 'xmss', 'lms',
    'picnic', 'newhope', 'frodokem', 'sike', 'sidh', 'mceliece', 'rainbow', 'bike', 'frodo', 'hqc'
}

OPS = {
    'view', 'encrypt', 'decrypt', 'sign', 'verify', 'hash', 'hmac', 'init', 'init_ex', 'update', 'final',
    'cleanup', 'free', 'auth', 'new', 'create', 'destroy', 'generate', 'derive', 'derivekey', 'keygen',
    'load', 'save', 'read', 'write', 'open', 'close', 'pubkey', 'privkey', 'pwdhash', 'compute', 'seal',
    'open', 'box', 'secretbox', 'pwhash', 'aead', 'keypair', 'randombytes', 'get', 'set', 'seed', 'reseed',
    'wrap', 'unwrap', 'pad', 'unpad', 'mac', 'authenticate', 'derivebits', 'export', 'import', 'validate',
    'rekey', 'rotate', 'split', 'combine', 'exchange', 'verifykey', 'signkey', 'encapsulate', 'decapsulate'
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
}

PQC_ALGOS = {
    'crystals-kyber', 'kyber',
    'crystals-dilithium', 'dilithium',
    'falcon',
    'sphincs+',
    'xmss', 'lms',
    'picnic',
    'newhope',
    'frodokem',
}

HEURISTIC_SAFE = {
    'blake3', 'sha3_256', 'sha3_384', 'sha3_512', 'shake128', 'shake256',
    'ed25519', 'ed448', 'curve25519', 'x25519',
}

SAFE_ALGOS_COMBINED = PQC_ALGOS | HEURISTIC_SAFE


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

def tokenize_and_recombine(name_part: str, known_algos: set) -> list[str]:
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

    max_words = 1
    if known_algos:
       max_words = max((a.count('_') + a.count('-') + 1 for a in known_algos), default=1)
       max_words = min(max_words, 4)

    while i < len(lowercase_tokens):
        found_match = False
        for length in range(min(max_words, len(lowercase_tokens) - i), 0, -1):
             potential_combo_direct = "".join(lowercase_tokens[i : i + length])
             potential_combo_hyphen = "-".join(lowercase_tokens[i : i + length])
             potential_combo_under = "_".join(lowercase_tokens[i : i + length])

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
            recombined.append(lowercase_tokens[i])
            i += 1

    return recombined

def classify(func_name: str, group: str, library: str) -> str:
    name_part_func = get_relevant_name_part(func_name, library)
    tokens_func = tokenize_and_recombine(name_part_func, ALGOS)

    algs_func = sorted(list(set(t for t in tokens_func if t in ALGOS)))
    ops_func = sorted(list(set(t for t in tokens_func if t in OPS)))

    category_parts = []

    if ops_func:
        category_parts.append("_".join(ops_func))
    if algs_func:
        category_parts.append("_".join(algs_func))

    if category_parts:
        return "_".join(category_parts) 

    name_part_group = get_relevant_name_part(group, library) 
    tokens_group = tokenize_and_recombine(name_part_group, ALGOS)

    algs_group = sorted(list(set(t for t in tokens_group if t in ALGOS)))
    ops_group = sorted(list(set(t for t in tokens_group if t in OPS)))

    category_parts_group = []
    if ops_group:
        category_parts_group.append("_".join(ops_group))
    if algs_group:
        category_parts_group.append("_".join(algs_group))

    if category_parts_group:
        return "_".join(category_parts_group)

    return 'uncategorized'

def is_quantum_safe(func_name: str, group: str, library: str) -> bool:
    relevant_safe_algos = SAFE_ALGOS_COMBINED

    name_part_func = get_relevant_name_part(func_name, library)
    tokens_func = tokenize_and_recombine(name_part_func, relevant_safe_algos)

    for token in tokens_func:
        if token in relevant_safe_algos:
            return True 
        
    name_part_group = get_relevant_name_part(group, library)
    tokens_group = tokenize_and_recombine(name_part_group, relevant_safe_algos)

    for token in tokens_group:
        if token in relevant_safe_algos:
            return True 
        
    return False
