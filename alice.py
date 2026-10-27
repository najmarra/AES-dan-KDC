import argparse

import common as c
from peer import Peer, alice_distribute, cli


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", default="Alice")
    ap.add_argument("--peer-id", default="Bob")
    ap.add_argument("--kdc-ip", required=True)
    ap.add_argument("--kdc-port", type=int, default=5000)
    ap.add_argument("--bob-ip", required=True)
    ap.add_argument("--bob-port", type=int, default=5001)
    ap.add_argument("--key", help="master key Ka (jika kosong akan ditanya)")
    a = ap.parse_args()

    key = a.key or c.ask_key("Master key Alice (Ka, 16/24/32 karakter ASCII): ")
    peer = Peer(a.id, "alice", key, a.peer_id)
    kdc_addr, bob_addr = (a.kdc_ip, a.kdc_port), (a.bob_ip, a.bob_port)

    try:
        alice_distribute(peer, kdc_addr, bob_addr)
    except Exception as e:
        c.log(peer.id, f"! distribusi key gagal: {e}  (cek key/KDC/Bob, lalu /rekey)")
    cli(peer, kdc_addr, bob_addr)


if __name__ == "__main__":
    main()
