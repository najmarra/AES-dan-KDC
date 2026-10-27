import socket
import threading
import time

import aes
import common as c


class Peer:
    def __init__(self, my_id, role, master_key, peer_id=None):
        self.id = my_id
        self.role = role                
        self.master_key = master_key    
        self.peer_id = peer_id
        self.sock = None
        self.ks = None                
        self.n2 = None                 
        self.ready = False             

    def attach(self, sock):
        """Pasang socket dan mulai thread penerima."""
        self.sock = sock
        threading.Thread(target=self._recv_loop, args=(sock,), daemon=True).start()

    def _recv_loop(self, sock):
        try:
            rf = sock.makefile("r", encoding="ascii", newline="\n")
            for line in rf:
                self._handle(sock, line.strip())
        except (OSError, ValueError):
            pass
        finally:
            if self.sock is sock:
                self.sock, self.ready = None, False
                c.log(self.id, "koneksi ke lawan bicara terputus")

    def _handle(self, sock, line):
        parts = line.split("|")
        kind = parts[0]
        try:
            if kind == "STEP3" and self.role == "bob":
                c.log(self.id, f"[Langkah 3] terima E(Kb,[Ks||ID_A]) (hex) = {parts[1]}")
                plain = c.dec(self.master_key, parts[1])
                ks, ida = plain.split("|", 1)
                self.ks, self.peer_id, self.ready = ks, ida, False
                c.log(self.id, f"  dekripsi dgn Kb -> Ks={ks}, ID_A={ida}")
                self.n2 = c.new_nonce()
                cipher = c.enc(self.ks, str(self.n2))
                c.log(self.id, f"[Langkah 4] kirim E(Ks, N2) dgn N2={self.n2} (hex) = {cipher}")
                c.send(sock, "STEP4", cipher)

            elif kind == "STEP4" and self.role == "alice":
                c.log(self.id, f"[Langkah 4] terima E(Ks,N2) (hex) = {parts[1]}")
                n2 = int(c.dec(self.ks, parts[1]))
                cipher = c.enc(self.ks, str(c.f(n2)))
                c.log(self.id, f"  N2={n2} -> f(N2)={c.f(n2)}")
                c.log(self.id, f"[Langkah 5] kirim E(Ks, f(N2)) (hex) = {cipher}")
                c.send(sock, "STEP5", cipher)
                self.ready = True
                c.log(self.id, "** Kanal aman siap, silakan ketik pesan **")

            elif kind == "STEP5" and self.role == "bob":
                c.log(self.id, f"[Langkah 5] terima E(Ks,f(N2)) (hex) = {parts[1]}")
                val = int(c.dec(self.ks, parts[1]))
                if val == c.f(self.n2):
                    self.ready = True
                    c.log(self.id, f"  f(N2) cocok ({val}) -> {self.peer_id} terautentikasi")
                    c.log(self.id, "** Kanal aman siap, silakan ketik pesan **")
                else:
                    c.log(self.id, f"  ! f(N2) TIDAK cocok (dapat {val}, harus {c.f(self.n2)}) -> putus")
                    sock.close()

            elif kind == "MSG":
                if not self.ks:
                    c.log(self.id, "! pesan masuk tapi belum ada session key")
                    return
                text = c.dec(self.ks, parts[1])
                c.log(self.id, f"<< ciphertext (hex): {parts[1]}")
                c.log(self.id, f"<< plaintext dari {self.peer_id}: {text}")
        except Exception as e:          
            c.log(self.id, f"! gagal memproses {kind}: {e}")

    def send_chat(self, text):
        if not (self.ready and self.sock and self.ks):
            print("  ! kanal belum siap (selesaikan langkah 1-5 dulu)")
            return
        try:
            text.encode("ascii")
        except UnicodeEncodeError:
            print("  ! plaintext harus ASCII")
            return
        cipher = c.enc(self.ks, text)
        c.log(self.id, f">> plaintext : {text}")
        c.log(self.id, f">> Ks        : {self.ks}")
        c.log(self.id, f">> ciphertext (hex): {cipher}")
        c.send(self.sock, "MSG", cipher)


def alice_distribute(peer, kdc_addr, bob_addr):
    """Jalankan langkah 1-3 (langkah 4-5 ditangani thread penerima)."""
    n1 = c.new_nonce()
    c.log(peer.id, f"[Langkah 1] kirim ke KDC: {peer.id} || {peer.peer_id} || N1={n1}")
    with socket.create_connection(kdc_addr, timeout=10) as s:
        c.send(s, "STEP1", peer.id, peer.peer_id, str(n1))
        line = s.makefile("r", encoding="ascii", newline="\n").readline().strip()
    parts = line.split("|")
    if parts[0] != "STEP2" or len(parts) != 3:
        raise RuntimeError("KDC menolak / format salah: " + "|".join(parts[1:]))
    c.log(peer.id, f"[Langkah 2] terima E(Ka,[Ks||ID_B||N1]) (hex) = {parts[1]}")
    c.log(peer.id, f"            terima E(Kb,[Ks||ID_A])     (hex) = {parts[2]}")
    plain = c.dec(peer.master_key, parts[1])
    ks, idb, n1_back = plain.split("|", 2)
    ticket = parts[2]                    
    if idb != peer.peer_id or n1_back != str(n1):
        raise RuntimeError("ID_B / N1 pada balasan KDC tidak cocok (replay/tampered?)")
    c.log(peer.id, f"  dekripsi dgn Ka -> Ks={ks}, ID_B={idb}, N1 cocok ({n1_back})")
    peer.ks, peer.ready = ks, False

    if peer.sock is None:
        sock = socket.create_connection(bob_addr, timeout=10)
        sock.settimeout(None)
        peer.attach(sock)
    c.log(peer.id, f"[Langkah 3] teruskan tiket ke Bob (hex) = {ticket}")
    c.send(peer.sock, "STEP3", ticket)

    for _ in range(50):                 
        if peer.ready:
            return True
        time.sleep(0.1)
    c.log(peer.id, "! handshake dengan Bob belum selesai")
    return False


def cli(peer, kdc_addr=None, bob_addr=None):
    print("Perintah: /key <key> | /rekey (Alice) | /status | /quit | teks lain = kirim pesan")
    while True:
        try:
            line = input()
        except (EOFError, KeyboardInterrupt):
            break
        line = line.strip()
        if not line:
            continue
        if line == "/quit":
            break
        elif line == "/status":
            print(f"  id={peer.id} lawan={peer.peer_id} master_key={peer.master_key} "
                  f"Ks={peer.ks} siap={peer.ready} mode={c.MODE}")
        elif line.startswith("/key"):
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                print("  pakai: /key <16/24/32 karakter ASCII>")
                continue
            try:
                aes.ascii_key(parts[1])
            except ValueError as e:
                print("  ! " + str(e))
                continue
            peer.master_key = parts[1]
            print("  master key diganti. Samakan di KDC:  /setkey " + peer.id + " " + parts[1])
        elif line == "/rekey" and peer.role == "alice":
            try:
                alice_distribute(peer, kdc_addr, bob_addr)
            except Exception as e:
                c.log(peer.id, f"! distribusi key gagal: {e}")
        else:
            peer.send_chat(line)
