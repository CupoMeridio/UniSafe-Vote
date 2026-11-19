"""
Shamir Secret Sharing (k-su-n) per l'escrow della chiave di decifratura dell'AE.

Il segreto (la chiave AES-256 che protegge la chiave privata RSA dell'AE) viene
diviso in n quote consegnate a n scrutatori distinti. Servono almeno k quote
per ricostruirlo; con k-1 quote o meno non si ottiene alcuna informazione sul
segreto (sicurezza information-theoretic, non solo computazionale).

Costruzione (Shamir, 1979):
- si sceglie un polinomio casuale f(x) = s + a1*x + ... + a(k-1)*x^(k-1)
  su un campo primo GF(P), con termine noto s uguale al segreto;
- la quota i-esima è il punto (i, f(i)), per i = 1..n;
- k punti determinano un unico polinomio di grado k-1: il segreto si ottiene
  come f(0) tramite interpolazione di Lagrange.

Il primo P = 2^521 - 1 (primo di Mersenne) è più grande di qualunque segreto
di 32 byte. Si usano solo la libreria standard (secrets per la casualità,
pow(x, -1, P) per gli inversi modulari).
"""

import secrets
from typing import List, Tuple

PRIME = 2 ** 521 - 1
Share = Tuple[int, int]  # (x, y) con x in 1..n


def split_secret(secret: bytes, n: int, k: int) -> List[Share]:
    """
    Divide un segreto in n quote, di cui k sufficienti a ricostruirlo.

    Args:
        secret: segreto da proteggere (es. chiave AES di 32 byte).
        n: numero di quote (scrutatori).
        k: soglia minima di quote per la ricostruzione (2 <= k <= n).
    """
    if not 2 <= k <= n:
        raise ValueError("Serve 2 <= k <= n")
    s = int.from_bytes(secret, "big")
    if s >= PRIME:
        raise ValueError("Segreto troppo grande per il campo")
    # Coefficienti casuali del polinomio; il termine noto è il segreto.
    coefficients = [s] + [secrets.randbelow(PRIME) for _ in range(k - 1)]

    def f(x: int) -> int:
        result = 0
        for coefficient in reversed(coefficients):  # schema di Horner
            result = (result * x + coefficient) % PRIME
        return result

    return [(x, f(x)) for x in range(1, n + 1)]


def combine_shares(shares: List[Share], secret_length: int = 32) -> bytes:
    """
    Ricostruisce il segreto da almeno k quote (interpolazione di Lagrange in 0).

    Con meno di k quote il risultato è un valore privo di relazione con il
    segreto: chi lo usa come chiave AES ottiene un errore di autenticazione
    (AES-GCM), quindi un numero insufficiente di quote viene sempre rilevato.
    """
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("Quote duplicate")
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        numerator, denominator = 1, 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                numerator = (numerator * -xj) % PRIME
                denominator = (denominator * (xi - xj)) % PRIME
        secret = (secret + yi * numerator * pow(denominator, -1, PRIME)) % PRIME
    if secret.bit_length() > secret_length * 8:
        # Valore fuori dall'intervallo dei segreti validi: quote insufficienti
        # o manomesse. Si restituisce comunque un valore della lunghezza
        # attesa, che fallirà la verifica AES-GCM.
        secret %= 2 ** (secret_length * 8)
    return secret.to_bytes(secret_length, "big")
