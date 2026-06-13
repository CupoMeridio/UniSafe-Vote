
"""
Modulo per la cifratura e decifratura RSA-OAEP.

RSA-OAEP (Optimal Asymmetric Encryption Padding) è un metodo di padding
per RSA che garantisce maggiore sicurezza rispetto al padding PKCS#1 v1.5.
Utilizza SHA-256 come funzione hash e MGF1 (Mask Generation Function).

Questo modulo viene utilizzato dal client per cifrare il voto e il seed,
e dall'Autorità Elettorale (AE) per decifrarli solo dopo la chiusura delle urne.

Implementazione con seed iniettabile
------------------------------------
A differenza della API ad alto livello di `cryptography` (che genera il seed
OAEP internamente in modo non controllabile), questo modulo implementa
EME-OAEP secondo RFC 8017 (PKCS#1 v2.2) consentendo di fornire esplicitamente
il seed di padding. Questo rende la cifratura DETERMINISTICA dato il seed:
chiunque conosca (messaggio, seed, chiave pubblica) può rieseguire la
cifratura e ottenere esattamente lo stesso ciphertext.

Questa proprietà è il fondamento della verifica universale descritta nel WP2:
a scrutinio concluso l'AE pubblica (scheda cifrata, voto in chiaro, seed) e
qualunque osservatore può ricifrare e confrontare il risultato con la scheda
registrata nel Merkle Tree, verificando che l'AE non abbia alterato né
inventato alcuna decifratura.

NOTA DI SICUREZZA: la natura probabilistica e la sicurezza IND-CPA di OAEP
sono preservate finché il seed è scelto casualmente e usato una sola volta.
Il client genera il seed con un CSPRNG (os.urandom) e non lo riutilizza.
"""

import hashlib

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes


# Funzione hash usata da OAEP e MGF1 (coerente con il resto del progetto: SHA-256)
_HASH = hashlib.sha256
_HLEN = 32  # lunghezza in byte del digest SHA-256


def _i2osp(value: int, length: int) -> bytes:
    """Converte un intero non negativo in una stringa di byte di lunghezza fissa (RFC 8017)."""
    return value.to_bytes(length, byteorder="big")


def _os2ip(octets: bytes) -> int:
    """Converte una stringa di byte nel corrispondente intero (RFC 8017)."""
    return int.from_bytes(octets, byteorder="big")


def _mgf1(seed: bytes, length: int) -> bytes:
    """
    Mask Generation Function MGF1 basata su SHA-256 (RFC 8017, App. B.2.1).

    Args:
        seed (bytes): Seme da cui derivare la maschera.
        length (int): Lunghezza in byte della maschera richiesta.

    Returns:
        bytes: Maschera pseudo-casuale di `length` byte.
    """
    mask = b""
    counter = 0
    while len(mask) < length:
        c = _i2osp(counter, 4)
        mask += _HASH(seed + c).digest()
        counter += 1
    return mask[:length]


def _eme_oaep_encode(message: bytes, k: int, seed: bytes) -> bytes:
    """
    Codifica EME-OAEP di un messaggio (RFC 8017, Sez. 7.1.1) con seed fornito.

    Args:
        message (bytes): Messaggio da codificare.
        k (int): Lunghezza in byte del modulo RSA.
        seed (bytes): Seed di padding (deve essere lungo esattamente _HLEN byte).

    Returns:
        bytes: Blocco codificato EM di lunghezza k byte.
    """
    if len(seed) != _HLEN:
        raise ValueError(f"Il seed OAEP deve essere lungo {_HLEN} byte, ricevuti {len(seed)}")
    # Vincolo sulla lunghezza massima del messaggio per OAEP
    if len(message) > k - 2 * _HLEN - 2:
        raise ValueError("Messaggio troppo lungo per la cifratura RSA-OAEP")

    # lHash = Hash("") (label vuota, coerente con label=None della API standard)
    l_hash = _HASH(b"").digest()
    # Padding string: zeri seguiti da 0x01
    ps = b"\x00" * (k - len(message) - 2 * _HLEN - 2)
    db = l_hash + ps + b"\x01" + message

    db_mask = _mgf1(seed, k - _HLEN - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

    seed_mask = _mgf1(masked_db, _HLEN)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

    return b"\x00" + masked_seed + masked_db


def _eme_oaep_decode(em: bytes, k: int) -> bytes:
    """
    Decodifica EME-OAEP di un blocco codificato (RFC 8017, Sez. 7.1.2).

    Args:
        em (bytes): Blocco codificato (lunghezza k byte).
        k (int): Lunghezza in byte del modulo RSA.

    Returns:
        bytes: Messaggio originale.
    """
    l_hash = _HASH(b"").digest()

    y = em[0]
    masked_seed = em[1:1 + _HLEN]
    masked_db = em[1 + _HLEN:]

    seed_mask = _mgf1(masked_db, _HLEN)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))

    db_mask = _mgf1(seed, k - _HLEN - 1)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    l_hash_prime = db[:_HLEN]

    # Cerca il separatore 0x01 dopo il padding di zeri
    i = _HLEN
    while i < len(db) and db[i] == 0:
        i += 1

    if y != 0 or l_hash_prime != l_hash or i >= len(db) or db[i] != 1:
        raise ValueError("Errore di decodifica OAEP")

    return db[i + 1:]


def encrypt(public_key: RSAPublicKey, plaintext_bytes: bytes, seed: bytes = None) -> bytes:
    """
    Cifra un messaggio in bytes con RSA-OAEP.

    Se `seed` è fornito, la cifratura è deterministica e riproducibile da
    chiunque conosca (messaggio, seed, chiave pubblica): questo abilita la
    verifica universale descritta nel WP2. Se `seed` è None, viene generato
    internamente un seed casuale e la cifratura resta probabilistica.

    Args:
        public_key: Chiave pubblica RSA da utilizzare per la cifratura.
        plaintext_bytes (bytes): Messaggio da cifrare (deve essere in bytes).
        seed (bytes, optional): Seed di padding OAEP (esattamente 32 byte).

    Returns:
        bytes: Messaggio cifrato (ciphertext).
    """
    if seed is None:
        # Cifratura probabilistica standard (seed gestito dalla libreria)
        return public_key.encrypt(
            plaintext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # Cifratura deterministica con seed iniettato (EME-OAEP manuale + RSAEP)
    numbers = public_key.public_numbers()
    n, e = numbers.n, numbers.e
    k = (n.bit_length() + 7) // 8

    em = _eme_oaep_encode(plaintext_bytes, k, seed)
    m = _os2ip(em)
    c = pow(m, e, n)
    return _i2osp(c, k)


def decrypt(private_key: RSAPrivateKey, ciphertext_bytes: bytes) -> bytes:
    """
    Decifra un messaggio cifrato con RSA-OAEP.

    Il complementare di encrypt(). Funziona indipendentemente dal fatto che il
    ciphertext sia stato prodotto con seed iniettato o con seed casuale, perché
    in entrambi i casi lo schema di padding è EME-OAEP con SHA-256.

    Args:
        private_key: Chiave privata RSA corrispondente alla chiave pubblica.
        ciphertext_bytes (bytes): Messaggio cifrato da decifrare.

    Returns:
        bytes: Messaggio originale in chiaro.
    """
    numbers = private_key.private_numbers()
    pub = private_key.public_key().public_numbers()
    n, d = pub.n, numbers.d
    k = (n.bit_length() + 7) // 8

    c = _os2ip(ciphertext_bytes)
    m = pow(c, d, n)
    em = _i2osp(m, k)
    return _eme_oaep_decode(em, k)
