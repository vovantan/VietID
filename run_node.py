# ✅ run_node.py (đã chỉnh sửa để hỗ trợ biến môi trường trên Render)

import asyncio, os, json, ipaddress, ssl, socket, threading, time, argparse
from datetime import datetime, timedelta, timezone
from vietid17 import VietIDBlockchain, Wallet, Transaction, D_BFT_Consensus, hash_message, schnorr_sign
from p2p_node import P2PNode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from api_server import run_api
import requests


def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def generate_self_signed_cert(private_key, public_key, common_name, host_ip, validity_days=365):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"VN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Hanoi"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Cau Giay"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"VietID Blockchain"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(host_ip)]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    return cert


def load_or_generate_tls_certs(current_node_id: str, host_ip: str, all_validator_ids: list):
    data_dir = os.path.join(os.getcwd(), f"node_data_{current_node_id}")
    os.makedirs(data_dir, exist_ok=True)

    key_path = os.path.join(data_dir, f"{current_node_id}_key.pem")
    cert_path = os.path.join(data_dir, f"{current_node_id}.pem")

    if os.path.exists(key_path) and os.path.exists(cert_path):
        with open(key_path, "rb") as f:
            private_key_pem = f.read()
        with open(cert_path, "rb") as f:
            certificate_pem = f.read()
    else:
        private_key, public_key = generate_rsa_key_pair()
        certificate = generate_self_signed_cert(private_key, public_key, f"Node {current_node_id}", host_ip)
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
        with open(key_path, "wb") as f:
            f.write(private_key_pem)
        with open(cert_path, "wb") as f:
            f.write(certificate_pem)

    ssl_context_server = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context_server.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ssl_context_server.verify_mode = ssl.CERT_REQUIRED

    ssl_context_client = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context_client.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ssl_context_client.verify_mode = ssl.CERT_REQUIRED

    # Tải các chứng chỉ peer từ URL (Render cung cấp)
    peer_cert_urls = os.environ.get("PEER_CERT_URLS", "").split(",")
    for url in peer_cert_urls:
        try:
            peer_id = url.strip().split("/")[-1]
            peer_cert_path = os.path.join(os.getcwd(), f"node_data_{peer_id}", f"{peer_id}.pem")
            os.makedirs(os.path.dirname(peer_cert_path), exist_ok=True)
            if not os.path.exists(peer_cert_path):
                print(f"[TLS] 📡 Tải cert từ {url}")
                resp = requests.get(url, verify=False, timeout=5)
                if resp.status_code == 200:
                    with open(peer_cert_path, "w") as f:
                        f.write(resp.text)
                    print(f"[TLS] ✅ Lưu cert peer {peer_id}")
                else:
                    print(f"[TLS] ❌ Không tìm thấy cert tại {url}")
            ssl_context_server.load_verify_locations(cafile=peer_cert_path)
            ssl_context_client.load_verify_locations(cafile=peer_cert_path)
        except Exception as e:
            print(f"[TLS] ❌ Lỗi khi tải cert từ {url}: {e}")

    print("✅ SSLContext đã được cấu hình.")
    return private_key_pem, certificate_pem, ssl_context_server, ssl_context_client


async def main():
    node_id = os.environ.get("NODE_ID")
    shard_id = int(os.environ.get("SHARD_ID", "0"))
    node_host = os.environ.get("NODE_HOST", "0.0.0.0")
    node_port = int(os.environ.get("P2P_PORT", "9000"))
    api_port = int(os.environ.get("PORT", "5001"))
    is_validator = os.environ.get("IS_VALIDATOR", "true").lower() == "true"
    all_validator_ids = os.environ.get("ALL_VALIDATOR_IDS", "").split(",")

    private_key_pem_tls, certificate_pem_tls, ssl_server_ctx, ssl_client_ctx = load_or_generate_tls_certs(
        node_id, node_host, all_validator_ids)

    blockchain = VietIDBlockchain(node_id, shard_id)
    blockchain.validator_shards = {
        0: ["node1"],
        1: ["node2"],
        2: ["node3"]
    }

    wallet_dir = os.path.join(os.getcwd(), f"node_data_{node_id}")
    os.makedirs(wallet_dir, exist_ok=True)
    wallet_file = os.path.join(wallet_dir, f"wallet_{node_id}.json")

    if os.path.exists(wallet_file):
        with open(wallet_file, 'r') as f:
            wallet_data = json.load(f)
        private_key_pem = wallet_data.get("private_key_pem", "").encode("utf-8")
        sender_wallet = Wallet(private_key_pem=private_key_pem)
    else:
        sender_wallet = Wallet()
        with open(wallet_file, 'w') as f:
            json.dump({
                "private_key_pem": sender_wallet.private_key_pem.decode('utf-8'),
                "public_key_pem": sender_wallet.public_key_pem.decode('utf-8'),
                "alias": sender_wallet.alias,
                "address": sender_wallet.address
            }, f, indent=4)
    print(f"✅ Wallet: {sender_wallet.address}")

    node = P2PNode(
        node_id=node_id,
        host=node_host,
        port=node_port,
        blockchain=blockchain,
        ssl_context_server=ssl_server_ctx,
        ssl_context_client=ssl_client_ctx
    )
    blockchain.p2p_node = node
    node.message_processor_task = asyncio.create_task(node._process_message_queue())

    validators = blockchain.validator_shards.get(shard_id, [])

    consensus = D_BFT_Consensus(
        blockchain=blockchain,
        node_id=node_id,
        p2p_node=node,
        is_primary=is_validator,
        validator_private_key_ecc=sender_wallet.private_key_ecc,
        validator_public_key_ecc=sender_wallet.public_key_ecc,
        validators=validators,
        view_timeout=10,
        tx_batch_size=3
    )

    blockchain.dbft_consensus = consensus
    node.consensus = consensus

    threading.Thread(target=run_api, args=(blockchain, node, sender_wallet), daemon=True).start()

    # Kết nối tới các PEER nếu có
    peer_nodes = os.environ.get("PEER_NODES", "").split(",")
    for peer in peer_nodes:
        try:
            peer_id, peer_host, peer_port = peer.split(":")
            asyncio.create_task(node.connect_to_peer(peer_host, int(peer_port), node_id))
        except Exception as e:
            print(f"[P2P] ❌ Lỗi PEER_NODES parse: {peer} → {e}")

    tasks = [
        asyncio.create_task(node.run_server()),
        asyncio.create_task(consensus.run_consensus_loop()),
    ]

    try:
        await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        print("[Main] ❗ Dừng bởi người dùng.")
    finally:
        print("[Main] 🔻 Dọn dẹp node...")
        if node.server:
            node.server.close()
            await node.server.wait_closed()
        if node.message_processor_task:
            node.message_processor_task.cancel()
            try:
                await node.message_processor_task
            except asyncio.CancelledError:
                pass
        if consensus.consensus_loop_task:
            consensus.consensus_loop_task.cancel()
            try:
                await consensus.consensus_loop_task
            except asyncio.CancelledError:
                pass

if __name__ == "__main__":
    asyncio.run(main())
