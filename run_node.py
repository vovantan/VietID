import asyncio, os, json, ipaddress, ssl, socket, threading, time
from datetime import datetime, timedelta, timezone
from vietid17 import VietIDBlockchain, Wallet, Transaction, D_BFT_Consensus, hash_message, schnorr_sign
from p2p_node import P2PNode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from api_server import run_api

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


def broadcast_node_info(node_id, host, port):
    msg = json.dumps({"id": node_id, "host": host, "port": port}).encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while True:
        try:
            s.sendto(msg, ('255.255.255.255', 50001))
        except Exception as e:
            print(f"[Broadcast] ❌ Lỗi khi gửi: {e}")
        time.sleep(5)

async def listen_for_nodes(current_node_id, node: P2PNode):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', 50001))
    s.setblocking(False)

    loop = asyncio.get_event_loop()
    known_peers = set()

    while True:
        try:
            data = await loop.sock_recv(s, 1024)
            info = json.loads(data.decode())
            key = f"{info['host']}:{info['port']}"
            if (key not in known_peers
                and info['id'] != current_node_id
                and not (info['host'] == node.host and info['port'] == node.port)):
                await node.connect_to_peer(info['host'], info['port'], info['id'])
                known_peers.add(key)

        except Exception as e:
            print(f"[Discovery] ❌ Broadcast error: {e}")
        await asyncio.sleep(1)


async def main():
    import argparse
    from api_server import run_api

    parser = argparse.ArgumentParser()
    parser.add_argument('--node_id', required=True)
    parser.add_argument('--shard_id', type=int, required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--is_validator', type=bool, default=True, help='Set to True if this node is a validator in its shard')
    parser.add_argument('--all_validator_ids', required=True, help='Comma-separated list of ALL validator node IDs in the network') # Tất cả validator IDs trong mạng

    args = parser.parse_args()

    node_id = args.node_id
    shard_id = args.shard_id
    node_port = args.port
    node_host = args.host
    is_validator = args.is_validator
    all_validator_ids = args.all_validator_ids.split(',')
    all_validator_ids.sort() # Sắp xếp để đảm bảo thứ tự nhất quán khi tải certs

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
        print(f"✅ Đã tải ví từ: {wallet_file}")
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

    consensus = D_BFT_Consensus(
        blockchain=blockchain,
        node_id=node_id,
        p2p_node=node,
        is_primary=is_validator, # is_primary phụ thuộc vào việc node này có phải là validator trong shard không
        validator_private_key_ecc=sender_wallet.private_key_ecc,
        validator_public_key_ecc=sender_wallet.public_key_ecc,
        validators=validators,
        view_timeout=10,
        tx_batch_size=3
    )
    
    blockchain.dbft_consensus = consensus
    node.consensus = consensus

    threading.Thread(target=run_api, args=(blockchain, node, sender_wallet), daemon=True).start()
    threading.Thread(target=broadcast_node_info, args=(node_id, node_host, node_port), daemon=True).start()

    tasks = [
        asyncio.create_task(node.run_server()),
        asyncio.create_task(consensus.run_consensus_loop()),
        asyncio.create_task(listen_for_nodes(node_id, node))
    ]

    try:
        await asyncio.gather(*tasks)
    except Exception as e:
        print(f"[Main] ❌ Lỗi khi chạy node: {e}")
        import traceback
        traceback.print_exc()
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
