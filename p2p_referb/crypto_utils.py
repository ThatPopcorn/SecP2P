# crypto_utils.py
import os
import base64
import logging
import struct
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag

# --- Constants ---
SIGNING_KEY_SIZE = 32  # Ed25519 private key size
EXCHANGE_KEY_SIZE = 32  # X25519 private key size
AES_KEY_SIZE = 32  # AES-256
NONCE_SIZE = 12  # AES-GCM recommended nonce size
HKDF_INFO_SESSION = (
    b"p2p_chat_aes_session_key"  # Context for main session key derivation
)
HKDF_INFO_MESSAGE = (
    b"p2p_chat_aes_message_key"  # Context for per-message key derivation
)
KEY_EXCHANGE_NONCE_SIZE = 32  # Size for replay protection nonce
SAS_INFO = b"p2p_chat_SAS_derivation_v1"  # Context for SAS HKDF
SAS_LENGTH_BYTES = 6  # Derive 6 bytes for SAS (e.g., 3x 16-bit numbers)
SAS_NUMBER_COUNT = 3  # How many numbers to display

# --- NEW Double Ratchet Constants ---
DR_HKDF_SALT_LEN = 32  # Length of salt for HKDF (using SHA256 output length)
DR_HKDF_INFO_RK = b"p2p_chat_dr_root_key"  # Info for deriving new Root Key
DR_HKDF_INFO_CK = b"p2p_chat_dr_chain_key"  # Info for deriving new Chain Key
DR_MESSAGE_KEY_SEED = b"\x01"  # Seed byte for deriving Message Key from Chain Key
DR_CHAIN_KEY_SEED = (
    b"\x02"  # Seed byte for deriving next Chain Key from current Chain Key
)
DR_MAX_SKIPPED_MESSAGES = 100  # Limit how many skipped message keys we store

# --- Setup Logging ---
log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

# --- Key Generation ---
def generate_signing_keys():
    """Generates a new Ed25519 key pair for signing."""
    log.debug("Generating new Ed25519 signing key pair.")
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def generate_exchange_keys():
    """Generates a new X25519 key pair for key exchange."""
    log.debug("Generating new X25519 exchange key pair.")
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


# --- Serialization / Deserialization ---
def serialize_public_key(public_key):
    """Serializes a public key to bytes (Raw format)."""
    if isinstance(public_key, (ed25519.Ed25519PublicKey, x25519.X25519PublicKey)):
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    else:
        log.error(
            f"Attempted to serialize unsupported public key type: {type(public_key)}"
        )
        raise TypeError("Unsupported public key type")


def deserialize_public_signing_key(key_bytes):
    """Deserializes bytes into an Ed25519 public key."""
    try:
        return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
    except Exception as e:
        log.error(f"Error deserializing Ed25519 public signing key: {e}")
        return None


def deserialize_public_exchange_key(key_bytes):
    """Deserializes bytes into an X25519 public key."""
    try:
        return x25519.X25519PublicKey.from_public_bytes(key_bytes)
    except Exception as e:
        log.error(f"Error deserializing X25519 public exchange key: {e}")
        return None


# --- Fingerprint ---
def get_fingerprint(public_signing_key_bytes):
    """Generates a SHA-256 hash of the public signing key bytes for verification."""
    try:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(public_signing_key_bytes)
        # Use first 16 hex chars (8 bytes) for brevity - reasonable collision resistance for manual check
        return digest.finalize().hex()[:16]
    except Exception as e:
        log.error(f"Error generating fingerprint: {e}")
        return None


# --- Signing and Verification ---
def sign_data(private_signing_key, data):
    """Signs data using the private Ed25519 key."""
    log.debug(f"Signing data of length {len(data)} bytes.")
    return private_signing_key.sign(data)


def verify_signature(public_signing_key, signature, data):
    """Verifies a signature using the public Ed25519 key."""
    log.debug(f"Verifying signature for data of length {len(data)} bytes.")
    try:
        public_signing_key.verify(signature, data)
        log.debug("Signature verified successfully.")
        return True
    except InvalidSignature:
        log.warning("Signature verification failed: InvalidSignature")
        return False
    except Exception as e:
        log.error(f"Unexpected error during signature verification: {e}")
        return False


# --- Key Exchange and Derivation ---
def perform_key_exchange(my_private_exchange_key, peer_public_exchange_key):
    """Performs X25519 key exchange to get a shared secret."""
    log.debug("Performing X25519 key exchange.")
    try:
        shared_secret = my_private_exchange_key.exchange(peer_public_exchange_key)
        log.debug(f"Shared secret generated (length: {len(shared_secret)} bytes).")
        return shared_secret
    except Exception as e:
        log.exception("Error during X25519 key exchange.")
        raise  # Re-raise after logging


def derive_session_key(shared_secret):
    """Derives the main symmetric AES session key from the shared secret using HKDF."""
    # Note: This isn't strictly needed anymore if only deriving message keys,
    # but kept in case a base session key is useful later.
    log.debug("Deriving session key using HKDF.")
    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=None,
            info=HKDF_INFO_SESSION,
        )
        return hkdf.derive(shared_secret)
    except Exception as e:
        log.exception("Error deriving session key.")
        raise


# --- SAS Derivation ---
def calculate_sas_input_hash(
    host_sign_pub_bytes,
    client_sign_pub_bytes,
    host_exch_pub_bytes,
    client_exch_pub_bytes,
    nonce_bytes,
    shared_secret,
):
    """Calculates the SHA-256 hash of all relevant exchange data for SAS input."""
    try:
        log.debug("Calculating SAS input hash.")
        hasher = hashes.Hash(hashes.SHA256())
        # Order matters! Both sides MUST concatenate in the same order.
        hasher.update(host_sign_pub_bytes)
        hasher.update(client_sign_pub_bytes)
        hasher.update(host_exch_pub_bytes)
        hasher.update(client_exch_pub_bytes)
        hasher.update(nonce_bytes)
        hasher.update(shared_secret)  # Use the provisional shared secret
        return hasher.finalize()
    except Exception as e:
        log.exception("Error calculating SAS input hash.")
        return None


def derive_sas_bytes(sas_input_hash):
    """Derives the raw SAS bytes using HKDF."""
    if not sas_input_hash:
        return None
    log.debug("Deriving SAS bytes using HKDF.")
    try:
        hkdf_sas = HKDF(
            algorithm=hashes.SHA256(),
            length=SAS_LENGTH_BYTES,
            salt=None,  # Salt isn't strictly needed when using a strong hash as IKM
            info=SAS_INFO,
        )
        return hkdf_sas.derive(sas_input_hash)
    except Exception as e:
        log.exception("Error deriving SAS bytes.")
        return None


def encode_sas_to_numbers(sas_bytes):
    """Encodes raw SAS bytes into a human-readable string of numbers."""
    if not sas_bytes or len(sas_bytes) != SAS_LENGTH_BYTES:
        log.error(
            f"Invalid sas_bytes length for number encoding: {len(sas_bytes) if sas_bytes else 'None'}"
        )
        return "Error"
    try:
        # Unpack bytes into numbers (e.g., 3 x 16-bit unsigned short integers)
        # Adjust format string based on SAS_LENGTH_BYTES and SAS_NUMBER_COUNT
        # '>' for big-endian, 'H' for unsigned short (2 bytes)
        numbers = struct.unpack(f">{SAS_NUMBER_COUNT}H", sas_bytes)
        # Format as zero-padded 5-digit numbers for easy comparison
        sas_string = " ".join([f"{num:05d}" for num in numbers])
        log.debug(f"Encoded SAS: {sas_string}")
        return sas_string
    except Exception as e:
        log.exception("Error encoding SAS bytes to numbers.")
        return "Error"


def dr_hkdf_rk(rk, dh_out):
    """
    Performs the Root Key update step of the Double Ratchet using HKDF-SHA256.
    Returns (new_rk, new_chain_key).
    """
    # Use the old Root Key as the HKDF salt
    salt = rk
    # Use the DH output as the Input Key Material (IKM)
    ikm = dh_out
    log.debug(f"Deriving new RK/CK. Salt len: {len(salt)}, IKM len: {len(ikm)}")
    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE * 2,  # Derive 32 bytes for new RK, 32 for new CK
            salt=salt,
            info=DR_HKDF_INFO_RK,
        )
        derived_bytes = hkdf.derive(ikm)
        new_rk = derived_bytes[:AES_KEY_SIZE]
        new_ck = derived_bytes[AES_KEY_SIZE:]
        log.debug(f"Derived new RK (len {len(new_rk)}) and CK (len {len(new_ck)})")
        return new_rk, new_ck
    except Exception as e:
        log.exception("Error during Root Key HKDF derivation.")
        return None, None


def dr_kdf_ck(ck):
    """
    Performs the Chain Key update step (deriving Message Key and next Chain Key).
    Uses HMAC-SHA256 as specified in Signal's DR.
    Returns (message_key, next_chain_key).
    """
    if not ck or len(ck) != AES_KEY_SIZE:
        log.error(
            f"Invalid Chain Key provided to dr_kdf_ck (len: {len(ck) if ck else 'None'})."
        )
        return None, None

    try:
        # Derive Message Key using HMAC with seed 0x01
        hmac_mk = hmac.HMAC(ck, hashes.SHA256())
        hmac_mk.update(DR_MESSAGE_KEY_SEED)
        message_key = hmac_mk.finalize()
        if len(message_key) != AES_KEY_SIZE:  # Should be 32 bytes from SHA256
            log.error(f"Derived message key has unexpected length: {len(message_key)}")
            # Handle potential length mismatch (though standard HMAC-SHA256 should be 32)
            # อาจจะต้อง truncate หรือ pad แต่ควรตรวจสอบ hmac implementation
            # For safety, return None if length is wrong.
            return None, None

        # Derive next Chain Key using HMAC with seed 0x02
        hmac_ck = hmac.HMAC(ck, hashes.SHA256())
        hmac_ck.update(DR_CHAIN_KEY_SEED)
        next_chain_key = hmac_ck.finalize()
        if len(next_chain_key) != AES_KEY_SIZE:
            log.error(
                f"Derived next chain key has unexpected length: {len(next_chain_key)}"
            )
            return message_key, None  # Return MK if derived, but signal CK failure

        # log.debug(f"Derived MK (len {len(message_key)}) and next CK (len {len(next_chain_key)}) from current CK.")
        return message_key, next_chain_key
    except Exception as e:
        log.exception("Error during Chain Key KDF.")
        return None, None


# --- Symmetric Encryption / Decryption (AES-GCM - Modified to take AD) ---
def dr_encrypt(message_key, plaintext, associated_data):
    """Encrypts using AES-GCM with associated data."""
    if not message_key or len(message_key) != AES_KEY_SIZE:
        log.error("Invalid message key for encryption.")
        return None
    try:
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(message_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data)
        # Return nonce + ciphertext
        return nonce + ciphertext
    except Exception as e:
        log.exception("Error during Double Ratchet encryption.")
        return None


def dr_decrypt(message_key, nonce_ciphertext, associated_data):
    """Decrypts using AES-GCM with associated data."""
    if not message_key or len(message_key) != AES_KEY_SIZE:
        log.error("Invalid message key for decryption.")
        return None
    if not nonce_ciphertext or len(nonce_ciphertext) < NONCE_SIZE:
        log.error("Invalid ciphertext length for decryption.")
        return None
    try:
        nonce = nonce_ciphertext[:NONCE_SIZE]
        ciphertext = nonce_ciphertext[NONCE_SIZE:]
        aesgcm = AESGCM(message_key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext_bytes.decode("utf-8")
    except InvalidTag:
        log.warning(
            "Decryption failed: Invalid AEAD Tag. Message corrupted or AD mismatch."
        )
        return None
    except Exception as e:
        log.exception("Error during Double Ratchet decryption.")
        return None


# --- Helper for Base64 Encoding/Decoding ---
def encode_base64(data_bytes):
    """Encodes bytes to Base64 string."""
    return base64.b64encode(data_bytes).decode("utf-8")


def decode_base64(data_str):
    """Decodes Base64 string to bytes."""
    try:
        return base64.b64decode(data_str)
    except (ValueError, TypeError) as e:
        log.error(f"Base64 Decode Error: {e}")
        return None
