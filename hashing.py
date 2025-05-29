import bcrypt

class Hash:
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hashes a password using bcrypt.
        Args:
            password: The plain-text password.
        Returns:
            The hashed password as a string.
        """
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password.decode('utf-8')

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Verifies a plain-text password against a hashed password.
        Args:
            plain_password: The plain-text password to verify.
            hashed_password: The stored hashed password.
        Returns:
            True if the password matches, False otherwise.
        """
        try:
            return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
        except ValueError: # Handles potential errors if hashed_password is not a valid hash
            return False
