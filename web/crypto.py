from cryptography.fernet import Fernet


def encrypt(plaintext: str, key: str) -> str:
    f = Fernet(key.encode() if isinstance(key, str) else key)
    return f.encrypt(plaintext.encode()).decode()


def decrypt(token: str, key: str) -> str:
    f = Fernet(key.encode() if isinstance(key, str) else key)
    return f.decrypt(token.encode()).decode()
