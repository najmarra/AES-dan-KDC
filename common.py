import secrets
import string
import time

import aes

MODE = "CBC"          
ALNUM = string.ascii_letters + string.digits


def enc(key: str, text: str) -> str:
    """Enkripsi string ASCII dengan key ASCII -> ciphertext dalam HEX."""
    k = aes.ascii_key(key)
    data = text.encode("ascii")
    ct = aes.encrypt_cbc(k, data) if MODE == "CBC" else aes.encrypt_ecb(k, data)
    return ct.hex()


def dec(key: str, hex_cipher: str) -> str:
    """Dekripsi ciphertext HEX -> string ASCII."""
    k = aes.ascii_key(key)
    ct = bytes.fromhex(hex_cipher)
    pt = aes.decrypt_cbc(k, ct) if MODE == "CBC" else aes.decrypt_ecb(k, ct)
    return pt.decode("ascii")


def new_session_key() -> str:
    """Session key Ks: 16 karakter ASCII alfanumerik acak (AES-128)."""
    return "".join(secrets.choice(ALNUM) for _ in range(16))


def new_nonce() -> int:
    return secrets.randbelow(900000) + 100000     


def f(n: int) -> int:
    """Fungsi f(N2) pada langkah 5. Di sini: f(N) = N - 1 (ubah bila di PPT beda)."""
    return n - 1


def send(sock, kind: str, *fields: str):
    sock.sendall((kind + "|" + "|".join(fields) + "\n").encode("ascii"))


def log(tag: str, msg: str):
    print(f"[{time.strftime('%H:%M:%S')}] [{tag}] {msg}", flush=True)


def ask_key(prompt: str) -> str:
    """Minta key ASCII (16/24/32 karakter) sampai valid."""
    while True:
        k = input(prompt).strip()
        try:
            aes.ascii_key(k)
            return k
        except ValueError as e:
            print("  ! " + str(e))
