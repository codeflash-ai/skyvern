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


        # Precompute derived key for this instance, since secret_key and salt do not change
        self._derived_key: bytes | None = None

    def method(self) -> EncryptMethod:
        return EncryptMethod.AES

    def _derive_key(self) -> bytes:
        # Optimization: Cache the key derivation for this instance, since it is expensive and can be reused
        if self._derived_key is None:
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
            padded_plaintext = self._pad(plaintext.encode("utf-8"))
            ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
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
        padding_length = block_size - (len(data) % block_size)
        # Optimized for both performance and clarity: avoid constructing list object
        # (bytes(n * [x]) is slower than bytes([x]) * n)
        padding = bytes([padding_length]) * padding_length
        return data + padding

    def _unpad(self, data: bytes) -> bytes:
        padding_length = data[-1]
        return data[:-padding_length]
