"""Primitives cryptographiques du coffre.

Choix de sécurité (voir README > Sécurité pour le détail) :

* Dérivation de clé : **Argon2id** (RFC 9106), via l'implémentation native
  de `cryptography` (>= 44, `hazmat.primitives.kdf.argon2`) si elle est
  disponible, sinon via `argon2-cffi` (paquet Debian `python3-argon2`, qui
  s'appuie sur libargon2, l'implémentation de référence des auteurs
  d'Argon2). Debian 13 fournit `cryptography` 43, dépourvue d'Argon2id :
  c'est le cas du paquet .deb. Argon2id étant normalisé, les deux produisent
  exactement la même clé pour les mêmes paramètres (vérifié par les tests,
  qui comparent les deux octet par octet). Aucune cryptographie n'est
  réinventée ici.
* Chiffrement : **AES-256-GCM** (chiffrement authentifié), via le même
  paquet, backend OpenSSL.
* Aléa : exclusivement `secrets` / `os.urandom` (CSPRNG du système),
  jamais le module `random`.
* Chiffrement en enveloppe : le mot de passe maître ne chiffre JAMAIS
  directement les données. Il ne sert qu'à envelopper (wrap) une clé de
  données aléatoire (DEK) générée à la création du coffre. Cela permet de
  changer le mot de passe maître sans avoir à rechiffrer toutes les données,
  et évite que la moindre donnée du coffre ne soit jamais directement liée
  cryptographiquement au mot de passe maître.

Aucune fonction de ce module ne journalise de matériel sensible.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:  # cryptography >= 44
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id as _CryptographyArgon2id
except ImportError:  # ex. Debian 13 : cryptography 43
    _CryptographyArgon2id = None

try:  # argon2-cffi (Debian : python3-argon2)
    from argon2.low_level import Type as _Argon2Type
    from argon2.low_level import hash_secret_raw as _argon2_hash_secret_raw
except ImportError:
    _argon2_hash_secret_raw = None

if _CryptographyArgon2id is None and _argon2_hash_secret_raw is None:
    raise ImportError(
        "Argon2id indisponible : installez cryptography >= 44 (pip) ou le paquet "
        "Debian python3-argon2 (sudo apt install python3-argon2)."
    )

ARGON2_BACKENDS = tuple(
    name for name, available in (
        ("cryptography", _CryptographyArgon2id is not None),
        ("argon2-cffi", _argon2_hash_secret_raw is not None),
    ) if available
)
ARGON2_BACKEND = ARGON2_BACKENDS[0]  # celui utilisé par défaut

# --- Constantes de dimensionnement ------------------------------------------------

SALT_SIZE = 16          # octets — recommandation Argon2id
NONCE_SIZE = 12          # octets — taille standard pour AES-GCM
KEY_SIZE = 32            # octets — AES-256
TAG_SIZE = 16            # octets — tag d'authentification GCM (fin du chiffré)
FORMAT_VERSION_ENTRY = 1  # version du format des blobs chiffrés individuels

# Bornes des paramètres Argon2id relus depuis un fichier (défauts : 3 / 64 Mio / 4).
MAX_ARGON2_TIME_COST = 64
MAX_ARGON2_MEMORY_KIB = 1024 * 1024  # 1 Gio
MAX_ARGON2_PARALLELISM = 64
# Bornes d'un sel relu depuis un fichier : 8 octets est le minimum d'Argon2
# (RFC 9106) ; l'application en génère toujours SALT_SIZE.
MIN_SALT_SIZE = 8
MAX_SALT_SIZE = 64

# Ré-exposée pour que les appelants puissent attraper les échecs
# d'authentification GCM sans importer `cryptography` directement.
AuthenticationFailed = InvalidTag


@dataclass(frozen=True, slots=True)
class Argon2Params:
    """Paramètres Argon2id associés à un coffre.

    Stockés en clair dans les métadonnées du coffre (ils ne sont pas
    secrets) afin de pouvoir faire évoluer les paramètres par défaut dans
    le futur sans casser la compatibilité avec les coffres existants.

    Les valeurs par défaut visent un compromis sécurité/performance
    raisonnable sur un poste de bureau (~300-600 ms de dérivation), en
    cohérence avec les recommandations OWASP pour Argon2id.
    """

    time_cost: int = 3          # itérations
    memory_cost: int = 65536    # Ko => 64 Mo
    parallelism: int = 4        # lanes
    hash_len: int = KEY_SIZE

    def to_dict(self) -> dict:
        return {
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "hash_len": self.hash_len,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Argon2Params:
        """Relit des paramètres stockés dans un fichier, en les bornant.

        Ces valeurs viennent de fichiers potentiellement piégés (coffre modifié,
        en-tête de sauvegarde, export reçu) : sans bornes, un fichier pourrait
        exiger des téraoctets de mémoire ou des milliards d'itérations et
        bloquer l'application avant même la vérification du mot de passe.
        Lève ValueError si une valeur sort des bornes.
        """
        params = cls(
            time_cost=int(data["time_cost"]),
            memory_cost=int(data["memory_cost"]),
            parallelism=int(data["parallelism"]),
            hash_len=int(data.get("hash_len", KEY_SIZE)),
        )
        if not (
            1 <= params.time_cost <= MAX_ARGON2_TIME_COST
            and 1 <= params.parallelism <= MAX_ARGON2_PARALLELISM
            and 8 * params.parallelism <= params.memory_cost <= MAX_ARGON2_MEMORY_KIB
            and params.hash_len == KEY_SIZE
        ):
            raise ValueError("Paramètres Argon2id hors des bornes autorisées.")
        return params


def check_salt(salt: object) -> bytes:
    """Valide un sel relu depuis un fichier (coffre, sauvegarde, export).

    Lève ValueError, que l'appelant traduit en erreur de fichier corrompu :
    sans ce contrôle, un sel trop court n'échouait qu'au cœur d'Argon2id.
    """
    if not isinstance(salt, bytes) or not MIN_SALT_SIZE <= len(salt) <= MAX_SALT_SIZE:
        raise ValueError("Sel Argon2id invalide.")
    return salt


# --- Génération d'aléa cryptographiquement sûr ------------------------------------


def generate_salt(size: int = SALT_SIZE) -> bytes:
    return secrets.token_bytes(size)


def generate_nonce(size: int = NONCE_SIZE) -> bytes:
    return secrets.token_bytes(size)


def generate_key(size: int = KEY_SIZE) -> bytes:
    """Génère une clé aléatoire (utilisé notamment pour la DEK du coffre)."""
    return secrets.token_bytes(size)


# --- Dérivation de clé (Argon2id) -------------------------------------------------


def derive_key(password: str, salt: bytes, params: Argon2Params) -> bytes:
    """Dérive une clé de `params.hash_len` octets à partir du mot de passe maître.

    Le mot de passe n'est jamais conservé ; seule la clé dérivée l'est,
    temporairement, en mémoire.
    """
    return _derive_key_with(ARGON2_BACKEND, password, salt, params)


def _derive_key_with(backend: str, password: str, salt: bytes, params: Argon2Params) -> bytes:
    """Argon2id (version 0x13) avec l'implémentation demandée."""
    secret = password.encode("utf-8")
    if backend == "cryptography" and _CryptographyArgon2id is not None:
        return _CryptographyArgon2id(
            salt=salt,
            length=params.hash_len,
            iterations=params.time_cost,
            lanes=params.parallelism,
            memory_cost=params.memory_cost,
        ).derive(secret)
    if backend == "argon2-cffi" and _argon2_hash_secret_raw is not None:
        return _argon2_hash_secret_raw(
            secret=secret,
            salt=salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_cost,
            parallelism=params.parallelism,
            hash_len=params.hash_len,
            type=_Argon2Type.ID,
            version=19,
        )
    raise ValueError(f"Implémentation Argon2id indisponible : {backend}")


def derive_subkey(key: bytes, info: bytes, length: int = KEY_SIZE) -> bytes:
    """Dérive une sous-clé indépendante d'une clé maître (HKDF-SHA256, RFC 5869).

    Séparation des usages : par exemple la clé des sauvegardes est dérivée de
    la DEK avec un `info` propre, au lieu de réutiliser la DEK telle quelle.
    """
    if len(key) != KEY_SIZE:
        raise ValueError("La clé maître doit faire 32 octets.")
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(key)


# --- Chiffrement authentifié (AES-256-GCM) ----------------------------------------


def aes_gcm_encrypt(
    key: bytes, plaintext: bytes, associated_data: bytes | None = None
) -> tuple[bytes, bytes]:
    """Chiffre `plaintext` avec une clé AES-256 et un nonce aléatoire unique.

    Retourne (nonce, ciphertext) où `ciphertext` inclut le tag d'authentification
    (comportement standard d'AESGCM du paquet `cryptography`).

    IMPORTANT : un nonce ne doit JAMAIS être réutilisé avec la même clé.
    C'est pourquoi un nonce aléatoire de 96 bits est généré à chaque appel :
    avec AES-GCM et un CSPRNG, le risque de collision est négligeable pour
    le volume de données géré par un coffre local.
    """
    if len(key) != KEY_SIZE:
        raise ValueError("La clé AES-256-GCM doit faire 32 octets.")
    nonce = generate_nonce()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def aes_gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """Déchiffre et authentifie `ciphertext`.

    Lève `AuthenticationFailed` (= `cryptography.exceptions.InvalidTag`) si
    la clé est incorrecte ou si les données ont été altérées. C'est à
    l'appelant (couche coffre) de traduire cet échec en
    `WrongMasterPasswordError` ou `VaultCorruptedError` selon le contexte,
    car cette couche crypto ne connaît pas cette distinction métier.
    """
    if len(key) != KEY_SIZE:
        raise ValueError("La clé AES-256-GCM doit faire 32 octets.")
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)


# --- Blob versionné (nonce + ciphertext) pour le stockage -------------------------


def pack_blob(nonce: bytes, ciphertext: bytes, version: int = FORMAT_VERSION_ENTRY) -> bytes:
    """Sérialise (version, nonce, ciphertext) en un seul BLOB pour SQLite.

    Format : 1 octet de version | NONCE_SIZE octets de nonce | reste = ciphertext.
    """
    if not (0 <= version <= 255):
        raise ValueError("Version de blob invalide.")
    return bytes([version]) + nonce + ciphertext


def unpack_blob(blob: bytes) -> tuple[int, bytes, bytes]:
    """Inverse de `pack_blob`. Lève ValueError si le blob est tronqué ou d'une version
    inconnue (l'octet de version n'est pas authentifié : seule la version écrite par
    l'application est acceptée, pour qu'il ne puisse jamais orienter le déchiffrement).
    """
    if not isinstance(blob, bytes) or len(blob) < 1 + NONCE_SIZE + TAG_SIZE:
        raise ValueError("Blob chiffré invalide ou tronqué.")
    version = blob[0]
    if version != FORMAT_VERSION_ENTRY:
        raise ValueError("Version de blob chiffré non prise en charge.")
    nonce = blob[1 : 1 + NONCE_SIZE]
    ciphertext = blob[1 + NONCE_SIZE :]
    return version, nonce, ciphertext


def encrypt_field(key: bytes, plaintext: str, associated_data: bytes | None = None) -> bytes:
    """Chiffre une valeur texte destinée à être stockée en base (BLOB)."""
    nonce, ciphertext = aes_gcm_encrypt(key, plaintext.encode("utf-8"), associated_data)
    return pack_blob(nonce, ciphertext)


def decrypt_field(key: bytes, blob: bytes, associated_data: bytes | None = None) -> str:
    """Déchiffre un BLOB produit par `encrypt_field`."""
    _version, nonce, ciphertext = unpack_blob(blob)
    plaintext = aes_gcm_decrypt(key, nonce, ciphertext, associated_data)
    return plaintext.decode("utf-8")


def wipe(buffer: bytearray) -> None:
    """Best-effort : écrase un buffer mutable en mémoire.

    Limite connue : CPython ne garantit pas l'absence de copies (interning,
    garbage collector, swap disque). Ceci réduit la fenêtre d'exposition,
    ce n'est pas une garantie absolue d'effacement mémoire.
    """
    for i in range(len(buffer)):
        buffer[i] = 0
