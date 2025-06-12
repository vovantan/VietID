import asyncio, os, json, ipaddress, ssl, requests
from datetime import datetime, timedelta, timezone
from vietid17 import VietIDBlockchain, Wallet, Transaction, D_BFT_Consensus, hash_message, schnorr_sign
from p2p_node import P2PNode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from api_server import run_api
import threading

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
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(host_ip))]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    return cert 

# Map node_id -> IP/host thực tế, tùy mạng của bạn
NODE_HOST_MAP = {
    "node_1_id_example_for_dbft": "127.0.0.1",
    "node_2_id_example_for_dbft": "127.0.0.1",
    "node_3_id_example_for_dbft": "127.0.0.1",
}


def load_or_generate_tls_certs(current_node_id: str, host_ip: str, all_validator_ids: list):
    data_dir = os.path.join(os.getcwd(), f"node_data_{current_node_id}")
    os.makedirs(data_dir, exist_ok=True)

    key_path = os.path.join(data_dir, f"{current_node_id}_key.pem")
    cert_path = os.path.join(data_dir, f"{current_node_id}.pem")

    # Tải hoặc tạo cert của chính node này
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

    # Khởi tạo SSLContext
    ssl_context_server = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context_server.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ssl_context_server.verify_mode = ssl.CERT_REQUIRED

    ssl_context_client = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context_client.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ssl_context_client.verify_mode = ssl.CERT_REQUIRED

    # Tải chứng chỉ từ các validator khác nếu chưa có
    for validator_id in all_validator_ids:
        if validator_id == current_node_id:
            continue

        peer_cert_path = os.path.join(os.getcwd(), f"node_data_{validator_id}", f"{validator_id}.pem")
        os.makedirs(os.path.dirname(peer_cert_path), exist_ok=True)

        if not os.path.exists(peer_cert_path):
            peer_host = NODE_HOST_MAP.get(validator_id, "127.0.0.1")
            url = f"https://{peer_host}:5000/cert/{validator_id}"
            try:
                print(f"[TLS] 📡 Đang tải cert của {validator_id} từ {url}")
                resp = requests.get(url, verify=False, timeout=5)
                if resp.status_code == 200:
                    with open(peer_cert_path, "w") as f:
                        f.write(resp.text)
                    print(f"[TLS] ✅ Đã lưu chứng chỉ của {validator_id} vào {peer_cert_path}")
                else:
                    print(f"[TLS] ❌ Không tìm thấy cert của {validator_id} tại {url}")
            except Exception as e:
                print(f"[TLS] ❌ Lỗi khi tải cert từ {url}: {e}")

        # Dù tải hay đã tồn tại, cố gắng load
        if os.path.exists(peer_cert_path):
            ssl_context_server.load_verify_locations(cafile=peer_cert_path)
            ssl_context_client.load_verify_locations(cafile=peer_cert_path)

    print("✅ SSLContext đã được cấu hình thành công.")
    return private_key_pem, certificate_pem, ssl_context_server, ssl_context_client

async def connect_after_delay(host: str, port: int, delay: int, current_node_id: str, p2p_node_instance: P2PNode):
    await asyncio.sleep(delay)
    if port != p2p_node_instance.port:
        try:
            await p2p_node_instance.connect_to_peer(host, port, current_node_id)
        except Exception as e:
            print(f"[P2P] ❌ Kết nối tới {host}:{port} thất bại: {e}")



async def main():
    node_id = "node_2_id_example_for_dbft"
    shard_id = 1
    node_port = 8766
    node_host = "127.0.0.1"
    is_validator = True

    all_validator_ids = [
        "node_1_id_example_for_dbft",
        "node_2_id_example_for_dbft",
        "node_3_id_example_for_dbft"
    ]
    all_validator_ids.sort()

    private_key_pem_tls, certificate_pem_tls, ssl_server_ctx, ssl_client_ctx = load_or_generate_tls_certs(node_id, node_host, all_validator_ids)

    blockchain = VietIDBlockchain(node_id, shard_id)

    SHARD_VALIDATOR_MAP = {
        0: ["node_1_id_example_for_dbft"],
        1: ["node_2_id_example_for_dbft"],
        2: ["node_3_id_example_for_dbft"]
    }
    validators = SHARD_VALIDATOR_MAP.get(shard_id, [])

    blockchain.validator_shards = SHARD_VALIDATOR_MAP

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
        print(f"✅ Ví mới đã được tạo và lưu tại: {wallet_file}")

    print(f"Ví đã được tạo. Địa chỉ: {sender_wallet.address}")

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

    # Sau đó truyền vào D_BFT_Consensus:
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
    # Sau khi tạo consensus:
    node.consensus = consensus

    tasks = [
        asyncio.create_task(node.run_server()),
        asyncio.create_task(consensus.run_consensus_loop())
    ]
    threading.Thread(target=run_api, args=(blockchain, node, sender_wallet)).start()
    try:
        await asyncio.gather(*tasks)
    except Exception as e:
        print(f"[Main] ❌ Lỗi khi chạy các tác vụ chính: {e}")


if __name__ == "__main__":
    asyncio.run(main())

