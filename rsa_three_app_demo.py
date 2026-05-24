from __future__ import annotations

import argparse
import base64
import json
import socket
import struct
import sys
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature


DEFAULT_HOST = "127.0.0.1"
APP2_PORT = 5001
APP3_PORT = 5002
BUFFER_SIZE = 4096


# ----------------------------
# Socket framing helpers
# ----------------------------
def send_frame(sock: socket.socket, data: bytes) -> None:
    """Send a length-prefixed frame."""
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes or raise ConnectionError."""
    chunks = []
    received = 0
    while received < n:
        chunk = sock.recv(min(BUFFER_SIZE, n - received))
        if not chunk:
            raise ConnectionError("Socket closed while receiving data")
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


def recv_frame(sock: socket.socket) -> bytes:
    """Receive a length-prefixed frame."""
    header = recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    return recv_exact(sock, length)


# ----------------------------
# RSA helpers
# ----------------------------
def generate_key_pair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def sign_message(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(public_key_pem: str, message: bytes, signature: bytes) -> bool:
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def public_key_to_pem(public_key: rsa.RSAPublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


# ----------------------------
# Data helpers
# ----------------------------
def pack_payload(message: str, signature: bytes, public_key_pem: str) -> bytes:
    obj: Dict[str, Any] = {
        "message": message,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "public_key_pem": public_key_pem,
    }
    return json.dumps(obj).encode("utf-8")


def unpack_payload(raw: bytes) -> Dict[str, Any]:
    return json.loads(raw.decode("utf-8"))


def pretty_print_payload(prefix: str, payload: Dict[str, Any]) -> None:
    print(f"\n[{prefix}] Message: {payload['message']}")
    print(f"[{prefix}] Signature (base64): {payload['signature_b64'][:80]}{'...' if len(payload['signature_b64']) > 80 else ''}")
    print(f"[{prefix}] Public key starts with: {payload['public_key_pem'].splitlines()[0]}")


def tamper_signature(signature_b64: str) -> str:
    raw = bytearray(base64.b64decode(signature_b64))
    if not raw:
        return signature_b64
    raw[0] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


# ----------------------------
# Application 1
# ----------------------------
def run_app1(host: str, port: int, message: str) -> None:
    private_key, public_key = generate_key_pair()
    public_key_pem = public_key_to_pem(public_key)
    signature = sign_message(private_key, message.encode("utf-8"))

    payload = pack_payload(message, signature, public_key_pem)

    print("[App 1] RSA key pair generated.")
    print("[App 1] Message signed successfully.")
    print(f"[App 1] Connecting to App 2 at {host}:{port} ...")

    with socket.create_connection((host, port)) as sock:
        send_frame(sock, payload)

    print("[App 1] Data sent to App 2.")
    print("[App 1] Original message:", message)
    print("[App 1] Signature (base64):", base64.b64encode(signature).decode("ascii"))


# ----------------------------
# Application 2
# ----------------------------
def run_app2(listen_host: str, listen_port: int, forward_host: str, forward_port: int) -> None:
    print(f"[App 2] Listening on {listen_host}:{listen_port} ...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((listen_host, listen_port))
        server.listen(1)

        conn, addr = server.accept()
        with conn:
            print(f"[App 2] Received connection from {addr[0]}:{addr[1]}")
            payload = unpack_payload(recv_frame(conn))
            pretty_print_payload("App 2 received", payload)

            print("\n[App 2] You can tamper with the signature here.")
            print("[App 2] Press Enter to flip one bit automatically.")
            print("[App 2] Or paste a replacement signature in base64.")
            print("[App 2] Type 'keep' to forward unchanged.")
            choice = input("[App 2] Your choice: ").strip()

            if choice.lower() == "keep":
                print("[App 2] Forwarding without changes.")
            elif choice:
                try:
                    base64.b64decode(choice, validate=True)
                    payload["signature_b64"] = choice
                    print("[App 2] Signature replaced with your input.")
                except Exception:
                    print("[App 2] Invalid base64. Applying automatic tamper instead.")
                    payload["signature_b64"] = tamper_signature(payload["signature_b64"])
            else:
                payload["signature_b64"] = tamper_signature(payload["signature_b64"])
                print("[App 2] Signature tampered by flipping one bit.")

            print(f"[App 2] Forwarding data to App 3 at {forward_host}:{forward_port} ...")
            forward_bytes = json.dumps(payload).encode("utf-8")

            with socket.create_connection((forward_host, forward_port)) as forward_sock:
                send_frame(forward_sock, forward_bytes)

            print("[App 2] Data forwarded to App 3.")


# ----------------------------
# Application 3
# ----------------------------
def run_app3(listen_host: str, listen_port: int) -> None:
    print(f"[App 3] Listening on {listen_host}:{listen_port} ...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((listen_host, listen_port))
        server.listen(1)

        conn, addr = server.accept()
        with conn:
            print(f"[App 3] Received connection from {addr[0]}:{addr[1]}")
            payload = unpack_payload(recv_frame(conn))
            pretty_print_payload("App 3 received", payload)

            message = payload["message"].encode("utf-8")
            signature = base64.b64decode(payload["signature_b64"])
            public_key_pem = payload["public_key_pem"]

            verified = verify_signature(public_key_pem, message, signature)
            print("\n[App 3] Signature verification result:", "VALID ✅" if verified else "INVALID ❌")
            if verified:
                print("[App 3] The message has not been altered after signing.")
            else:
                print("[App 3] Tampering detected: the signature no longer matches the message.")


# ----------------------------
# CLI
# ----------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="RSA three-application socket demo")
    sub = parser.add_subparsers(dest="mode", required=True)

    p1 = sub.add_parser("app1", help="Run Application 1 (sign and send)")
    p1.add_argument("--host", default=DEFAULT_HOST)
    p1.add_argument("--port", type=int, default=APP2_PORT)
    p1.add_argument("--message", default="Hello from Application 1")

    p2 = sub.add_parser("app2", help="Run Application 2 (tamper proxy)")
    p2.add_argument("--listen-host", default=DEFAULT_HOST)
    p2.add_argument("--listen-port", type=int, default=APP2_PORT)
    p2.add_argument("--forward-host", default=DEFAULT_HOST)
    p2.add_argument("--forward-port", type=int, default=APP3_PORT)

    p3 = sub.add_parser("app3", help="Run Application 3 (verify)")
    p3.add_argument("--listen-host", default=DEFAULT_HOST)
    p3.add_argument("--listen-port", type=int, default=APP3_PORT)

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        if args.mode == "app1":
            run_app1(args.host, args.port, args.message)
        elif args.mode == "app2":
            run_app2(args.listen_host, args.listen_port, args.forward_host, args.forward_port)
        elif args.mode == "app3":
            run_app3(args.listen_host, args.listen_port)
        else:
            raise ValueError(f"Unknown mode: {args.mode}")
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except ConnectionRefusedError as e:
        print(f"\nConnection error: {e}")
        return 1
    except ConnectionError as e:
        print(f"\nSocket error: {e}")
        return 1
    except Exception as e:
        print(f"\nError: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
