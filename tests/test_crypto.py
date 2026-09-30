import unittest

from app.core import crypto


class TestArgon2idDerivation(unittest.TestCase):
    def test_derive_key_is_deterministic_for_same_salt(self):
        salt = crypto.generate_salt()
        params = crypto.Argon2Params(time_cost=2, memory_cost=8192, parallelism=1)
        k1 = crypto.derive_key("correct horse battery staple", salt, params)
        k2 = crypto.derive_key("correct horse battery staple", salt, params)
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), params.hash_len)

    def test_derive_key_differs_with_different_salt(self):
        params = crypto.Argon2Params(time_cost=2, memory_cost=8192, parallelism=1)
        k1 = crypto.derive_key("same password", crypto.generate_salt(), params)
        k2 = crypto.derive_key("same password", crypto.generate_salt(), params)
        self.assertNotEqual(k1, k2)

    def test_derive_key_differs_with_different_password(self):
        salt = crypto.generate_salt()
        params = crypto.Argon2Params(time_cost=2, memory_cost=8192, parallelism=1)
        k1 = crypto.derive_key("password-one", salt, params)
        k2 = crypto.derive_key("password-two", salt, params)
        self.assertNotEqual(k1, k2)


class TestArgon2idReferenceVectors(unittest.TestCase):
    """Official vectors: every available implementation must reproduce them."""

    # libargon2 (phc-winner-argon2, src/test.c) : argon2id v=19 m=65536 t=2 p=1,
    # password "password", salt "somesalt".
    LIBARGON2_ID = bytes.fromhex(
        "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7")

    def test_libargon2_vector_with_every_backend(self):
        params = crypto.Argon2Params(time_cost=2, memory_cost=65536, parallelism=1)
        for backend in crypto.ARGON2_BACKENDS:
            key = crypto._derive_key_with(backend, "password", b"somesalt", params)
            self.assertEqual(key, self.LIBARGON2_ID, backend)

    @unittest.skipUnless("cryptography" in crypto.ARGON2_BACKENDS, "cryptography < 44")
    def test_rfc9106_section_5_3(self):
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

        tag = Argon2id(salt=b"\x02" * 16, length=32, iterations=3, lanes=4, memory_cost=32,
                       ad=b"\x04" * 12, secret=b"\x03" * 8).derive(b"\x01" * 32)
        self.assertEqual(tag.hex(),
                         "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")


@unittest.skipUnless(len(crypto.ARGON2_BACKENDS) == 2,
                     "only one Argon2id implementation installed (pip install argon2-cffi)")
class TestArgon2idBackendsEquivalence(unittest.TestCase):
    """cryptography and argon2-cffi (python3-argon2 on Debian) must be interchangeable."""

    def test_same_key_for_same_inputs(self):
        cases = [
            ("correct horse battery staple",
             crypto.Argon2Params(time_cost=2, memory_cost=8192, parallelism=1)),
            ("mot-de-passe-éàü-€",
             crypto.Argon2Params(time_cost=3, memory_cost=16384, parallelism=4)),
            ("", crypto.Argon2Params(time_cost=1, memory_cost=8, parallelism=1, hash_len=64)),
            ("paramètres par défaut", crypto.Argon2Params()),
        ]
        for password, params in cases:
            salt = crypto.generate_salt()
            a = crypto._derive_key_with("cryptography", password, salt, params)
            b = crypto._derive_key_with("argon2-cffi", password, salt, params)
            self.assertEqual(a, b, password)
            self.assertEqual(len(a), params.hash_len)

    def test_vault_created_with_one_backend_opens_with_the_other(self):
        import os
        import tempfile
        from unittest import mock

        from app.core.vault import Vault

        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {"XDG_DATA_HOME": tmp}):
            with mock.patch.object(crypto, "ARGON2_BACKEND", "cryptography"):
                Vault.create("croise", "Croisé", "mot-de-passe-de-test").close()
            with mock.patch.object(crypto, "ARGON2_BACKEND", "argon2-cffi"):
                Vault.unlock("croise", "mot-de-passe-de-test").close()


class TestAesGcm(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        key = crypto.generate_key()
        plaintext = b"donnee sensible confidentielle"
        nonce, ciphertext = crypto.aes_gcm_encrypt(key, plaintext)
        decrypted = crypto.aes_gcm_decrypt(key, nonce, ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_wrong_key_fails_authentication(self):
        key1 = crypto.generate_key()
        key2 = crypto.generate_key()
        nonce, ciphertext = crypto.aes_gcm_encrypt(key1, b"secret")
        with self.assertRaises(crypto.AuthenticationFailed):
            crypto.aes_gcm_decrypt(key2, nonce, ciphertext)

    def test_tampered_ciphertext_fails_authentication(self):
        key = crypto.generate_key()
        nonce, ciphertext = crypto.aes_gcm_encrypt(key, b"secret payload")
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        with self.assertRaises(crypto.AuthenticationFailed):
            crypto.aes_gcm_decrypt(key, nonce, bytes(tampered))

    def test_associated_data_must_match(self):
        key = crypto.generate_key()
        nonce, ciphertext = crypto.aes_gcm_encrypt(key, b"secret", associated_data=b"context-a")
        with self.assertRaises(crypto.AuthenticationFailed):
            crypto.aes_gcm_decrypt(key, nonce, ciphertext, associated_data=b"context-b")

    def test_nonces_are_unique_across_calls(self):
        key = crypto.generate_key()
        nonces = {crypto.aes_gcm_encrypt(key, b"x")[0] for _ in range(200)}
        self.assertEqual(len(nonces), 200)

    def test_rejects_wrong_key_size(self):
        with self.assertRaises(ValueError):
            crypto.aes_gcm_encrypt(b"trop-court", b"data")


class TestBlobPacking(unittest.TestCase):
    def test_pack_unpack_roundtrip(self):
        nonce = crypto.generate_nonce()
        ciphertext = b"ciphertext-bytes"
        blob = crypto.pack_blob(nonce, ciphertext)
        version, unpacked_nonce, unpacked_ct = crypto.unpack_blob(blob)
        self.assertEqual(version, crypto.FORMAT_VERSION_ENTRY)
        self.assertEqual(unpacked_nonce, nonce)
        self.assertEqual(unpacked_ct, ciphertext)

    def test_unpack_rejects_truncated_blob(self):
        with self.assertRaises(ValueError):
            crypto.unpack_blob(b"\x01\x02\x03")  # trop court


class TestFieldEncryption(unittest.TestCase):
    def test_encrypt_decrypt_field_roundtrip(self):
        key = crypto.generate_key()
        original = "mon-mot-de-passe-super-secret-éàü"
        blob = crypto.encrypt_field(key, original)
        self.assertNotIn(original.encode("utf-8"), blob)
        decrypted = crypto.decrypt_field(key, blob)
        self.assertEqual(decrypted, original)

    def test_decrypt_field_wrong_key_raises(self):
        key1 = crypto.generate_key()
        key2 = crypto.generate_key()
        blob = crypto.encrypt_field(key1, "secret")
        with self.assertRaises(crypto.AuthenticationFailed):
            crypto.decrypt_field(key2, blob)


if __name__ == "__main__":
    unittest.main()
