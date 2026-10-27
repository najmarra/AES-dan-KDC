import argparse
import socket
import threading

import aes
import common as c

keys = {}                 
next_ks = [None]           
lock = threading.Lock()


def handle(conn, addr):
    who = f"{addr[0]}:{addr[1]}"
    try:
        rf = conn.makefile("r", encoding="ascii", newline="\n")
        for line in rf:
            p = line.strip().split("|")
            if len(p) != 4 or p[0] != "STEP1":
                c.send(conn, "ERR", "format salah")
                continue
            _, ida, idb, n1 = p
            c.log("KDC", f"[Langkah 1] dari {who}: ID_A={ida} || ID_B={idb} || N1={n1}")

            with lock:
                ka, kb = keys.get(ida), keys.get(idb)
                if ka is None or kb is None:
                    c.log("KDC", f"  ! ID tidak terdaftar ({ida}/{idb})")
                    c.send(conn, "ERR", "ID tidak terdaftar")
                    continue
                ks = next_ks[0] or c.new_session_key()
                next_ks[0] = None

            ticket_plain = f"{ks}|{ida}"
            ticket = c.enc(kb, ticket_plain)

            resp_plain = f"{ks}|{idb}|{n1}"
            resp = c.enc(ka, resp_plain)

            c.log("KDC", f"  Session key Ks             = {ks}")
            c.log("KDC", f"  E(Ka,[Ks||ID_B||N1]) plain = {resp_plain}")
            c.log("KDC", f"  E(Ka,[Ks||ID_B||N1]) (hex) = {resp}")
            c.log("KDC", f"  E(Kb,[Ks||ID_A])     plain = {ticket_plain}")
            c.log("KDC", f"  E(Kb,[Ks||ID_A])     (hex) = {ticket}")
            c.log("KDC", "[Langkah 2] kirim E(Ka,[Ks||ID_B||N1]) || E(Kb,[Ks||ID_A])")
            c.send(conn, "STEP2", resp, ticket)
    except (OSError, ValueError) as e:
        c.log("KDC", f"koneksi {who} error: {e}")
    finally:
        conn.close()


def accept_loop(srv):
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


def set_key(ident, key):
    try:
        aes.ascii_key(key)
    except ValueError as e:
        print("  ! " + str(e))
        return
    with lock:
        keys[ident] = key
    print(f"  master key {ident} diperbarui")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--key", action="append", default=[], metavar="ID=KEY",
                    help="master key awal, contoh --key Alice=abcdefghijklmnop (boleh diulang)")
    a = ap.parse_args()

    for kv in a.key:
        ident, _, k = kv.partition("=")
        set_key(ident, k)
    for ident in ("Alice", "Bob"):
        if ident not in keys:
            keys[ident] = c.ask_key(f"Master key untuk {ident} (16/24/32 karakter ASCII): ")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.host, a.port))
    srv.listen(5)
    c.log("KDC", f"KDC aktif di {a.host}:{a.port}   (ketik /help untuk perintah)")
    threading.Thread(target=accept_loop, args=(srv,), daemon=True).start()

    while True:
        try:
            cmd = input().strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not cmd:
            continue
        parts = cmd.split()
        if parts[0] == "/quit":
            break
        elif parts[0] == "/keys":
            with lock:
                for i, k in keys.items():
                    print(f"  {i:10s} = {k}")
        elif parts[0] == "/setkey" and len(parts) == 3:
            set_key(parts[1], parts[2])
        elif parts[0] == "/nextks" and len(parts) == 2:
            k = parts[1]
            if len(k) == 16 and k.isascii() and "|" not in k:
                next_ks[0] = k
                print("  Ks untuk request berikutnya dipaksa:", k)
            else:
                print("  ! Ks harus 16 karakter ASCII tanpa karakter '|'")
        else:
            print("  perintah: /keys | /setkey <id> <key> | /nextks <key16> | /quit")


if __name__ == "__main__":
    main()
