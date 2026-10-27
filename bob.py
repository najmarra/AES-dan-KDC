import argparse
import socket
import threading

import common as c
from peer import Peer, cli


def accept_loop(srv, peer):
    while True:
        conn, addr = srv.accept()
        c.log(peer.id, f"koneksi masuk dari {addr[0]}:{addr[1]}")
        if peer.sock:
            try:
                peer.sock.close()
            except OSError:
                pass
        peer.attach(conn)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", default="Bob")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5001)
    ap.add_argument("--key", help="master key Kb (jika kosong akan ditanya)")
    a = ap.parse_args()

    key = a.key or c.ask_key("Master key Bob (Kb, 16/24/32 karakter ASCII): ")
    peer = Peer(a.id, "bob", key)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.host, a.port))
    srv.listen(5)
    c.log(peer.id, f"Bob menunggu Alice di {a.host}:{a.port}")
    threading.Thread(target=accept_loop, args=(srv, peer), daemon=True).start()
    cli(peer)


if __name__ == "__main__":
    main()
