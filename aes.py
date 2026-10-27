import os

def _xtime(a):
    """Kalikan dengan x (=0x02) di GF(2^8)."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _gmul(a, b):
    """Perkalian dua byte di GF(2^8) (shift-and-add)."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sboxes():
    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _gmul(a, b) == 1:
                inv[a] = b
                break
    sbox = [0] * 256
    for i in range(256):
        x = inv[i]
        sbox[i] = x ^ _rotl8(x, 1) ^ _rotl8(x, 2) ^ _rotl8(x, 3) ^ _rotl8(x, 4) ^ 0x63
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return sbox, inv_sbox


SBOX, INV_SBOX = _build_sboxes()

RCON = []
_rc = 1
for _ in range(10):
    RCON.append(_rc)
    _rc = _xtime(_rc)


def expand_key(key: bytes):
    """Return list round key (tiap round key = 16 byte, urutan kolom)."""
    if len(key) not in (16, 24, 32):
        raise ValueError("Panjang key harus 16/24/32 byte")
    nk = len(key) // 4            
    nr = nk + 6                   
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = w[i - 1][:]
        if i % nk == 0:
            t = t[1:] + t[:1]                 
            t = [SBOX[b] for b in t]          
            t[0] ^= RCON[i // nk - 1]         
        elif nk > 6 and i % nk == 4:          
            t = [SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)]


def _add_round_key(s, rk):
    return [a ^ b for a, b in zip(s, rk)]


def _sub_bytes(s):
    return [SBOX[b] for b in s]


def _inv_sub_bytes(s):
    return [INV_SBOX[b] for b in s]


def _shift_rows(s):
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]   
    return out


def _inv_shift_rows(s):
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * ((c + r) % 4)] = s[r + 4 * c]   
    return out


def _mix_columns(s):
    out = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        out[4 * c + 0] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
        out[4 * c + 1] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
        out[4 * c + 2] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
        out[4 * c + 3] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)
    return out


def _inv_mix_columns(s):
    out = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        out[4 * c + 0] = _gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9)
        out[4 * c + 1] = _gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13)
        out[4 * c + 2] = _gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11)
        out[4 * c + 3] = _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14)
    return out


def encrypt_block(block: bytes, round_keys) -> bytes:
    nr = len(round_keys) - 1
    s = _add_round_key(list(block), round_keys[0])
    for r in range(1, nr):
        s = _sub_bytes(s)
        s = _shift_rows(s)
        s = _mix_columns(s)
        s = _add_round_key(s, round_keys[r])
    s = _sub_bytes(s)
    s = _shift_rows(s)
    s = _add_round_key(s, round_keys[nr])
    return bytes(s)


def decrypt_block(block: bytes, round_keys) -> bytes:
    nr = len(round_keys) - 1
    s = _add_round_key(list(block), round_keys[nr])
    for r in range(nr - 1, 0, -1):
        s = _inv_shift_rows(s)
        s = _inv_sub_bytes(s)
        s = _add_round_key(s, round_keys[r])
        s = _inv_mix_columns(s)
    s = _inv_shift_rows(s)
    s = _inv_sub_bytes(s)
    s = _add_round_key(s, round_keys[0])
    return bytes(s)


def pad(data: bytes) -> bytes:
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def unpad(data: bytes) -> bytes:
    if not data or len(data) % 16:
        raise ValueError("Panjang data tidak valid")
    n = data[-1]
    if n < 1 or n > 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("Padding tidak valid (key salah / data rusak)")
    return data[:-n]


def encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    rk = expand_key(key)
    data = pad(plaintext)
    return b"".join(encrypt_block(data[i:i + 16], rk) for i in range(0, len(data), 16))


def decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) % 16 or not ciphertext:
        raise ValueError("Panjang ciphertext bukan kelipatan 16")
    rk = expand_key(key)
    out = b"".join(decrypt_block(ciphertext[i:i + 16], rk) for i in range(0, len(ciphertext), 16))
    return unpad(out)


def encrypt_cbc(key: bytes, plaintext: bytes, iv: bytes = None) -> bytes:
    """Output = IV(16 byte) || ciphertext."""
    rk = expand_key(key)
    iv = iv or os.urandom(16)
    data = pad(plaintext)
    out, prev = bytearray(iv), iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = encrypt_block(blk, rk)
        out += prev
    return bytes(out)


def decrypt_cbc(key: bytes, data: bytes) -> bytes:
    if len(data) < 32 or len(data) % 16:
        raise ValueError("Panjang ciphertext tidak valid")
    rk = expand_key(key)
    prev, out = data[:16], bytearray()
    for i in range(16, len(data), 16):
        blk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(decrypt_block(blk, rk), prev))
        prev = blk
    return unpad(bytes(out))


def ascii_key(s: str) -> bytes:
    try:
        b = s.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("Key harus karakter ASCII")
    if len(b) not in (16, 24, 32):
        raise ValueError("Panjang key harus 16/24/32 karakter ASCII (AES-128/192/256)")
    return b


if __name__ == "__main__":
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    vectors = [
        ("AES-128", bytes(range(16)), "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("AES-192", bytes(range(24)), "dda97ca4864cdfe06eaf70a0ec0d7191"),
        ("AES-256", bytes(range(32)), "8ea2b7ca516745bfeafc49904b496089"),
    ]
    ok = True
    for name, k, expected in vectors:
        rk = expand_key(k)
        ct = encrypt_block(pt, rk)
        good = ct.hex() == expected and decrypt_block(ct, rk) == pt
        ok &= good
        print(f"{name}: {ct.hex()}  {'OK' if good else 'GAGAL'}")
    msg = b"Halo Bob, ini pesan rahasia dari Alice!"
    k = b"kunciRahasia1234"
    assert decrypt_cbc(k, encrypt_cbc(k, msg)) == msg
    assert decrypt_ecb(k, encrypt_ecb(k, msg)) == msg
    print("CBC/ECB round-trip: OK")
    print("SEMUA TEST LULUS" if ok else "ADA TEST GAGAL")
