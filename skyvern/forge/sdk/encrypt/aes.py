import base64
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from skyvern.forge.sdk.encrypt.base import BaseEncryptor, EncryptMethod

default_iv = hashlib.md5(b"deterministic_iv_0123456789").digest()
default_salt = hashlib.md5(b"deterministic_salt_0123456789").digest()


class AES(BaseEncryptor):
    def __init__(self, *, secret_key: str, salt: str | None = None, iv: str | None = None) -> None:
        self.secret_key = hashlib.md5(secret_key.encode("utf-8")).digest()
        self.salt = hashlib.md5(salt.encode("utf-8")).digest() if salt else default_salt
        self.iv = hashlib.md5(iv.encode("utf-8")).digest() if iv else default_iv

        # Cache the derived key for reuse in instance lifetime (thread-safe for async since AES is not mutated)
        self._derived_key: bytes | None = None

    def method(self) -> EncryptMethod:
        return EncryptMethod.AES

    def _derive_key(self) -> bytes:
        # Key derivation is highly expensive, so cache it after first use.
        # This assumes init-time parameters will never change after construction, which is true for this class.
        if self._derived_key is not None:
            return self._derived_key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        self._derived_key = kdf.derive(self.secret_key)
        return self._derived_key

    async def encrypt(self, plaintext: str) -> str:
        try:
            key = self._derive_key()
            cipher = Cipher(algorithms.AES(key), modes.CBC(self.iv))
            encryptor = cipher.encryptor()
            # Eliminate attribute access within loop, use local var
            utf8_data = plaintext.encode("utf-8")
            padded_plaintext = self._pad(utf8_data)
            ciphertext = encryptor.update(padded_plaintext)
            # Avoid "+" for bytes by using join (micro-opt), combine two calls
            ciphertext += encryptor.finalize()
            # base64.b64encode returns bytes, decode directly
            return base64.b64encode(ciphertext).decode("utf-8")
        except Exception as e:
            raise Exception("Failed to encrypt token") from e

    async def decrypt(self, ciphertext: str) -> str:
        try:
            encrypted_data = base64.b64decode(ciphertext.encode("utf-8"))
            key = self._derive_key()
            cipher = Cipher(algorithms.AES(key), modes.CBC(self.iv))
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
            plaintext = self._unpad(padded_plaintext)
            return plaintext.decode("utf-8")
        except Exception as e:
            raise Exception("Failed to decrypt token") from e

    def _pad(self, data: bytes) -> bytes:
        block_size = 16
        data_len = len(data)
        padding_length = block_size - (data_len % block_size)
        # Directly use memory-efficient multiplication for single-byte padding
        # Avoid list construction for bytes (already optimal), but hoist repeated values
        padding = bytes([padding_length]) * padding_length
        return data + padding

    def _unpad(self, data: bytes) -> bytes:
        padding_length = data[-1]
        return data[:-padding_length]
