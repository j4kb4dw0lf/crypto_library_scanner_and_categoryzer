import re

ALGOS = {
    "Block Ciphers": {
        "AES": ["aes", "aes128", "aes192", "aes256"],
        "DES": ["des", "3des", "tdes", "des-x", "des3"],
        "Camellia": ["camellia"],
        "ARIA": ["aria"],
        "SM4": ["sm4"],
        "Blowfish": ["blowfish", "blf"],
        "Twofish": ["twofish", "twf"],
        "Serpent": ["serpent"],
        "CAST": ["cast"],
        "IDEA": ["idea"],
        "SEED": ["seed"],
        "MARS": ["mars"],
        "RC2": ["rc2"]
    },
    "Stream Ciphers": {
        "ChaCha": ["chacha", "chacha20", "chacha20poly1305", "xchacha20", "chachapoly",  "xchacha20poly1305"],
        "Salsa20": ["salsa20", "xsalsa20", "xsalsa20poly1305", "salsa20poly1305"],
        "RC4": ["rc4"],
        "HC": ["hc128", "hc256"],
        "Rabbit": ["rabbit"],
        "Sosemanuk": ["sosemanuk"]
    },
    "AEAD": {
        "GCM": ["gcm"],
        "CCM": ["ccm"],
        "EAX": ["eax"],
        "OCB": ["ocb"],
    },
    "Modes of Operation": {
        "CTR": ["ctr"],
        "CBC": ["cbc"],
        "CFB": ["cfb"],
        "OFB": ["ofb"],
        "XTS-AES": ["xts"],
        "ECB": ["ecb"]
    },
    "Hashing Algorithms": {
        "SHA-general": ["sha"],
        "SHA-1": ["sha1"],
        "SHA-2": ["sha2", "sha224", "sha256", "sha384", "sha512", "sha512", "sha512"],
        "SHA-3": ["sha3", "sha3", "sha3", "sha3"],
        "MD": ["md2", "md4", "md5"],
        "BLAKE2": ["blake2b", "blake2s"],
        "BLAKE3": ["blake3"],
        "SM3": ["sm3"],
        "RIPEMD": ["ripemd160", "ripemd"],
        "Whirlpool": ["whirlpool"],
        "Tiger": ["tiger"],
        "Keccak": ["keccak"], 
        "SHAKE": ["shake128", "shake256"], 
        "Streebog": ["streebog"], 
        "GOST Hash": ["gosthash"]
    },
    "MACs": {
        "HMAC": ["hmac", "hmacsha", "hmacsha512256", "hmacsha512", "hmacsha256"],
        "CMAC": ["cmac"],
        "PMAC": ["pmac"],
        "Poly1305": ["poly1305"] 
    },
    "Public-Key Cryptography": {
        "Encryption & Key Exchange": {
            "RSA": ["rsa"],
            "ECIES": ["ecies"],
            "DH": ["dh"],
            "ECDH": ["ecdh"],
            "Curve25519": ["curve25519", "x25519"]
        },
        "Digital Signatures": {
            "RSA": ["rsa"], 
            "DSA": ["dsa"],
            "ECDSA": ["ecdsa", "ecdsap256", "ecdsap384", "ecdsap521"],
            "EdDSA": ["eddsa", "ed25519", "ed448", "sc25519"],
            "SM2": ["sm2"]
        },
        "PQC": {
            "KEMs": { 
                "Crystals-Kyber": ["crystals-kyber", "kyber"],
                "NewHope": ["newhope"],
                "FrodoKEM": ["frodokem", "frodo"],
                "SIKE": ["sike", "sidh"],
                "McEliece": ["mceliece"],
                "BIKE": ["bike"],
                "HQC": ["hqc"]
            },
            "Digital Signatures PQC": {
                "Crystals-Dilithium": ["crystals-dilithium", "dilithium"],
                "Falcon": ["falcon"],
                "SPHINCS+": ["sphincs+", "sphincs"],
                "XMSS": ["xmss"],
                "LMS": ["lms"],
                "Picnic": ["picnic"],
                "Rainbow": ["rainbow"]
            }
        }
    }
}

OPS = {
    "Core Crypto Operations": {
        "Encryption": ["encrypt", "seal", "box", "secretbox", "sbox", "aead", "wrap", "encapsulate"],
        "Decryption": ["decrypt", "unwrap", "decapsulate"],
        "Signing": ["sign", "signkey"],
        "Verification": ["verify", "verifykey"],
        "Hashing": ["hash", "pwdhash", "pwhash", "compute"],
        "Message Authentication": ["hmac", "mac", "authenticate"] 
    },
    "Key Management": {
        "Generation & Derivation": ["generate", "keygen", "keypair", "derive", "derivekey", "derivebits"],
        "Exchange": ["exchange"],
        "Lifecycle": ["create", "destroy", "rekey", "rotate"],
        "Material Handling": ["split", "combine"]
    },
    "Key Property Access": {
        "Public Key": ["pubkey"],
        "Private Key": ["privkey"]
    },
    "Randomness & Seeding": {
        "Random Number Generation": ["randombytes"],
        "Seed Management": ["seed", "reseed"]
    },
    "Data Processing": {
        "Padding": ["pad"],
        "Unpadding": ["unpad"]
    },
    "Validation & Integrity": {
        "Data Validation": ["validate"]
    },
    "Internal Primitives": {
        "S-Box Operation": ["sbox"]
    },
    "Others": {
        "Others": ["tls", "ssl", "x509", "cert", "signature", "keyexchange", "keyagreement"]
    }
}

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
    'openssl': {
        'prefixes': ['EVP_', 'evp_'],
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

def get_pqc_algos_from_structure(algos_data_structure):
    pqc_set = set()
    try:
        pqc_main = algos_data_structure.get("Public-Key Cryptography", {}).get("PQC", {})
        kems = pqc_main.get("KEMs", {})
        for algo_list in kems.values():
            pqc_set.update(algo_list)
        sigs_pqc = pqc_main.get("Digital Signatures PQC", {})
        for algo_list in sigs_pqc.values():
            pqc_set.update(algo_list)
    except Exception: 
        pass 
    return pqc_set

PQC_ALGOS_DERIVED = get_pqc_algos_from_structure(ALGOS)

HEURISTIC_SAFE = {
    'blake3', 'sha3_256', 'sha3_384', 'sha3_512', 'shake128', 'shake256',
    'ed25519', 'ed448', 'curve25519', 'x25519',
}

SAFE_ALGOS_COMBINED = PQC_ALGOS_DERIVED | HEURISTIC_SAFE

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
             potential_combo_direct = "".join(current_slice)
             potential_combo_hyphen = "-".join(current_slice)
             potential_combo_under = "_".join(current_slice)
             if potential_combo_direct in known_tokens:
                 recombined.append(potential_combo_direct)
                 i += length
                 found_match = True
                 break
             elif potential_combo_hyphen in known_tokens:
                  recombined.append(potential_combo_hyphen)
                  i += length
                  found_match = True
                  break
             elif potential_combo_under in known_tokens:
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
    tokens_func_for_algos = tokenize_and_recombine(name_part_func, ALL_ALGOS_FLAT)
    tokens_func_for_ops = tokenize_and_recombine(name_part_func, ALL_OPS_FLAT)
    algs_func = sorted(list(set(t for t in tokens_func_for_algos if t in ALL_ALGOS_FLAT)))
    ops_func = sorted(list(set(t for t in tokens_func_for_ops if t in ALL_OPS_FLAT)))
    category_parts = []
    if ops_func:
        category_parts.append("_".join(ops_func))
    if algs_func:
        category_parts.append("_".join(algs_func))
    if category_parts:
        return "_".join(category_parts) 
    name_part_group = get_relevant_name_part(group, library) 
    tokens_group_for_algos = tokenize_and_recombine(name_part_group, ALL_ALGOS_FLAT)
    tokens_group_for_ops = tokenize_and_recombine(name_part_group, ALL_OPS_FLAT)
    algs_group = sorted(list(set(t for t in tokens_group_for_algos if t in ALL_ALGOS_FLAT)))
    ops_group = sorted(list(set(t for t in tokens_group_for_ops if t in ALL_OPS_FLAT)))
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
