import pytest
from hashing import Hash

class TestHashing:
    def test_hash_password_generates_valid_hash(self):
        password = "securepassword123"
        hashed_password = Hash.hash_password(password)
        assert hashed_password is not None
        assert isinstance(hashed_password, str)
        assert len(hashed_password) > len(password) # Bcrypt hashes are typically longer
        assert password != hashed_password

    def test_verify_password_correct(self):
        password = "securepassword123"
        hashed_password = Hash.hash_password(password)
        assert Hash.verify_password(password, hashed_password) is True

    def test_verify_password_incorrect(self):
        password = "securepassword123"
        wrong_password = "wrongpassword"
        hashed_password = Hash.hash_password(password)
        assert Hash.verify_password(wrong_password, hashed_password) is False

    def test_verify_password_with_empty_string(self):
        password = ""
        hashed_password = Hash.hash_password(password)
        assert Hash.verify_password(password, hashed_password) is True

    def test_verify_password_with_malformed_hash(self):
        password = "securepassword123"
        malformed_hash = "not_a_real_bcrypt_hash"
        assert Hash.verify_password(password, malformed_hash) is False

    def test_different_passwords_produce_different_hashes(self):
        password_1 = "securepassword123"
        password_2 = "anotherSecurePassword456"
        hash_1 = Hash.hash_password(password_1)
        hash_2 = Hash.hash_password(password_2)
        assert hash_1 != hash_2

    def test_same_password_produces_different_hashes_due_to_salt(self):
        password = "securepassword123"
        hash_1 = Hash.hash_password(password)
        hash_2 = Hash.hash_password(password)
        # Bcrypt incorporates a salt, so two hashes of the same password should be different
        assert hash_1 != hash_2
        # But both should verify correctly
        assert Hash.verify_password(password, hash_1) is True
        assert Hash.verify_password(password, hash_2) is True
