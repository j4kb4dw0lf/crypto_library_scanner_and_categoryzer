import re

ALGOS = {
    "BlockCiphers": {
        "AES": ["aes", "aes128", "aes192", "aes256"],
        "DES": ["des", "3des", "tdes", "des-x", "des3", "desx"],
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
    "StreamCiphers": {
        "ChaCha": ["chacha", "chacha20", "chacha20poly1305", "xchacha20", "chachapoly", "xchacha20poly1305"],
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
    "HashingAlgorithms": {
        "SHA-general": ["sha"],
        "SHA-1": ["sha1"],
        "SHA-2": ["sha2", "sha224", "sha256", "sha384", "sha512"],
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
    "PublicKeyCryptography": {
        "Encryption & Key Exchange": {
            "RSA": ["rsa"],
            "ECIES": ["ecies"],
            "DH": ["dh"],
            "ECDH": ["ecdh"],
            "Curve25519": ["curve25519", "x25519"]
        }
    },
    "DigitalSignatures": {
        "RSA": ["rsa"],
        "DSA": ["dsa"],
        "ECDSA": ["ecdsa", "ecdsap256", "ecdsap384", "ecdsap521"],
        "EdDSA": ["eddsa", "ed25519", "ed448", "sc25519"],
        "SM2": ["sm2"]
    },
    "KEMs": {
        "Crystals-Kyber": ["crystals-kyber", "kyber"],
        "NewHope": ["newhope"],
        "FrodoKEM": ["frodokem", "frodo"],
        "SIKE": ["sike", "sidh"],
        "McEliece": ["mceliece"],
        "BIKE": ["bike"],
        "HQC": ["hqc"]
    },
    "DigitalSignaturesPQC": { 
        "Crystals-Dilithium": ["crystals-dilithium", "dilithium"],
        "Falcon": ["falcon"],
        "SPHINCS+": ["sphincs+", "sphincs"],
        "XMSS": ["xmss"],
        "LMS": ["lms"],
        "Picnic": ["picnic"],
        "Rainbow": ["rainbow"]
    }
}

OPS = {
    "CoreCryptoOperations": {
        "Encryption": ["encrypt", "seal", "box", "secretbox", "sbox", "aead", "wrap", "encapsulate"],
        "Decryption": ["decrypt", "unwrap", "decapsulate"],
        "Signing": ["sign", "signkey", "signature", "sig", "sigkey", "cert", "certificate"],
        "Verification": ["verify", "verifykey", "verifysig", "verifysig"],
        "Hashing": ["hash", "pwdhash", "pwhash", "compute"],
        "Message Authentication": ["hmac", "mac", "authenticate"]
    },
    "ModesofOperation": {
        "CTR": ["ctr"],
        "CBC": ["cbc"],
        "CFB": ["cfb"],
        "OFB": ["ofb"],
        "XTS-AES": ["xts"],
        "ECB": ["ecb"]
    },
    "KeyManagement": {
        "Generation & Derivation": ["generate", "keygen", "keypair", "derive", "derivekey", "derivebits"],
        "Exchange": ["exchange"],
        "Lifecycle": ["create", "destroy", "rekey", "rotate"],
        "Material Handling": ["split", "combine"]
    },
    "KeyPropertyAccess": {
        "Public Key": ["pubkey"],
        "Private Key": ["privkey"]
    },
    "RandomnessSeeding": {
        "Random Number Generation": ["randombytes"],
        "Seed Management": ["seed", "reseed"]
    },
    "DataProcessing": {
        "Padding": ["pad"],
        "Unpadding": ["unpad"]
    },
    "ValidationIntegrity": {
        "Data Validation": ["validate"]
    },
    "InternalPrimitives": {
        "S-Box Operation": ["sbox"]
    },
    "Others": {
        "Others": ["evp", "tls", "x509", "cert", "keyexchange", "keyagreement"]
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
        'namespaces': ['Botan', 'botan', 'botan::', 'Botan::']
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

ALGO_TOKEN_TO_MAIN_CLASSES = {}
for main_class, subcategories_dict in ALGOS.items():
    to_process_stack = [subcategories_dict]
    while to_process_stack:
        current_item = to_process_stack.pop()
        if isinstance(current_item, dict):
            for _key, value in current_item.items():
                if isinstance(value, list):
                    for algo_token in value:
                        if isinstance(algo_token, str):
                            ALGO_TOKEN_TO_MAIN_CLASSES.setdefault(algo_token, set()).add(main_class)
                elif isinstance(value, dict):
                    to_process_stack.append(value)
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
    def get_ops_and_algo_classes(name_part_str: str):
        tokens_for_algos_raw = tokenize_and_recombine(name_part_str, ALL_ALGOS_FLAT)
        tokens_for_ops_raw = tokenize_and_recombine(name_part_str, ALL_OPS_FLAT)

        # Get main OPS categories
        op_main_classes = set()
        for t_op in tokens_for_ops_raw:
            if t_op in OP_TOKEN_TO_MAIN_CLASSES:
                op_main_classes.update(OP_TOKEN_TO_MAIN_CLASSES[t_op])
        sorted_op_main_classes = sorted(list(op_main_classes))

        # Get main ALGOS categories
        algo_main_classes = set()
        for t_algo in tokens_for_algos_raw:
            if t_algo in ALGO_TOKEN_TO_MAIN_CLASSES:
                algo_main_classes.update(ALGO_TOKEN_TO_MAIN_CLASSES[t_algo])
        sorted_algo_main_classes = sorted(list(algo_main_classes))

        return sorted_op_main_classes, sorted_algo_main_classes

    name_part_f = get_relevant_name_part(func_name, library)
    ops_f, algo_classes_f = get_ops_and_algo_classes(name_part_f)
    if ops_f or algo_classes_f:
        category_parts = []
        if ops_f:
            category_parts.append("_".join(ops_f)) # Now this will be higher-level OPS categories
        if algo_classes_f:
            category_parts.append("_".join(algo_classes_f))
        result_str = "_".join(category_parts)
        # The "_OPERATION" suffix logic might need re-evaluation based on your exact naming preference
        # If you want "Core_Crypto_Operations" to be the only thing, then remove this suffix
        if ops_f and not algo_classes_f:
            result_str += "_OPERATION"
        return result_str

    name_part_g = get_relevant_name_part(group, library)
    ops_g, algo_classes_g = get_ops_and_algo_classes(name_part_g)
    if ops_g or algo_classes_g:
        category_parts = []
        if ops_g:
            category_parts.append("_".join(ops_g)) # Now this will be higher-level OPS categories
        if algo_classes_g:
            category_parts.append("_".join(algo_classes_g))
        result_str = "_".join(category_parts)
        if ops_g and not algo_classes_g:
            result_str += "_OPERATION"
        return result_str
    return 'uncategorized'

def get_pqc_algos_from_structure(algos_data_structure):
    pqc_set = set()
    kems_main = algos_data_structure.get("KEMs", {})
    for algo_list in kems_main.values():
        pqc_set.update(algo_list)
    sigs_pqc_main = algos_data_structure.get("DigitalSignaturesPQC", {})
    for algo_list in sigs_pqc_main.values():
        pqc_set.update(algo_list)
    return pqc_set

PQC_ALGOS_DERIVED = get_pqc_algos_from_structure(ALGOS)

HEURISTIC_SAFE = {
    'blake3', 'sha3_256', 'sha3_384', 'sha3_512', 'shake128', 'shake256',
    'ed25519', 'ed448', 'curve25519', 'x25519',
}

SAFE_ALGOS_COMBINED = PQC_ALGOS_DERIVED | HEURISTIC_SAFE

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
