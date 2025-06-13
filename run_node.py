import asyncio, os, json, ipaddress, ssl, socket, threading, time
import sys # Import sys to allow clean exit
import logging # Import logging module
try:
    import requests # Required for fetching peer certificates via HTTP(S)
except ImportError:
    logging.warning("Requests library not found. Cert fetching from external peers might fail.")
    requests = None # Set to None and handle gracefully

from datetime import datetime, timedelta, timezone
from vietid17 import VietIDBlockchain, Wallet, Transaction, D_BFT_Consensus, hash_message, schnorr_sign
from p2p_node import P2PNode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from api_server import run_api

# Configure basic logging for visibility on Render.com
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_rsa_key_pair():
    """Generates a new RSA private and public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_self_signed_cert(private_key, public_key, common_name, host_ip, validity_days=365):
    """Generates a self-signed X.509 certificate."""
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
            # Add DNSName for cloud environments where hostnames are common,
            # alongside IPAddress for robustness.
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.IPAddress(ipaddress.ip_address(host_ip))
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    return cert

def load_or_generate_tls_certs(current_node_id: str, host_ip: str, all_validator_ids: list):
    """
    Loads or generates TLS certificates for the current node and sets up SSL contexts.
    Attempts to fetch certificates from other peers if configured.
    """
    data_dir = os.path.join(os.getcwd(), f"node_data_{current_node_id}")
    os.makedirs(data_dir, exist_ok=True)
    logging.info(f"Đảm bảo thư mục dữ liệu nút tồn tại: {data_dir}")

    key_path = os.path.join(data_dir, f"{current_node_id}_key.pem")
    cert_path = os.path.join(data_dir, f"{current_node_id}.pem")

    logging.warning("Tạo chứng chỉ tự ký mới cho nút (Render có thể reset filesystem).")
    private_key, public_key = generate_rsa_key_pair()
    common_name = f"{current_node_id}.vietid.blockchain" # Use node_id as common name for cert

    # FIX: Corrected typo from IPv44Address to IPv4Address
    host_ip_for_cert = ipaddress.IPv4Address("127.0.0.1")

    certificate = generate_self_signed_cert(private_key, public_key, common_name, str(host_ip_for_cert))
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
    logging.info(f"Đã tạo chứng chỉ và khóa mới tại: {cert_path}, {key_path}")

    # Initialize SSLContexts
    ssl_context_server = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context_server.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ssl_context_server.verify_mode = ssl.CERT_REQUIRED
    ssl_context_server.check_hostname = False # Disable hostname check for self-signed/internal usage

    ssl_context_client = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context_client.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ssl_context_client.verify_mode = ssl.CERT_REQUIRED
    ssl_context_client.check_hostname = False # Disable hostname check for self-signed/internal usage

    # Fetch and load certificates from other validators, if configured via environment variables.
    # This assumes other validators expose their cert via a public URL (e.g., /cert endpoint).
    peer_cert_urls_str = os.environ.get("PEER_CERT_URLS", "")
    peer_cert_urls = [url.strip() for url in peer_cert_urls_str.split(',') if url.strip()]

    for peer_cert_url in peer_cert_urls:
        if requests: # Only attempt if 'requests' library is available
            try:
                logging.info(f"[TLS] 📡 Đang cố gắng tải cert từ URL: {peer_cert_url}")
                resp = requests.get(peer_cert_url, verify=False, timeout=5)
                resp.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
                
                temp_peer_cert_file = os.path.join(data_dir, f"temp_peer_{hash(peer_cert_url)}.pem")
                with open(temp_peer_cert_file, "w") as f:
                    f.write(resp.text)
                
                ssl_context_server.load_verify_locations(cafile=temp_peer_cert_file)
                ssl_context_client.load_verify_locations(cafile=temp_peer_cert_file)
                logging.info(f"[TLS] ✅ Đã tải và thêm chứng chỉ từ {peer_cert_url}.")
                os.remove(temp_peer_cert_file) # Clean up temporary file
            except requests.exceptions.RequestException as e:
                logging.error(f"[TLS] ❌ Lỗi khi tải cert từ {peer_cert_url}: {e}")
            except Exception as e:
                logging.error(f"[TLS] ❌ Lỗi không xác định khi xử lý cert từ {peer_cert_url}: {e}")
        else:
            logging.warning(f"[TLS] ⚠️ Requests library không có. Không thể tải chứng chỉ từ {peer_cert_url}.")

    logging.info("✅ SSLContext đã được cấu hình thành công.")
    return private_key_pem, certificate_pem, ssl_context_server, ssl_context_client


def broadcast_node_info(node_id, host, port):
    """
    This function is adapted for Render.com.
    UDP broadcast (255.255.255.255) typically does not work across instances in cloud environments.
    This function now primarily serves for logging the node's startup information.
    The original continuous loop for broadcasting is removed.
    """
    logging.info(f"[NODE_INFO] Node {node_id} đang hoạt động tại {host}:{port}")


async def listen_for_nodes(current_node_id, node: P2PNode):
    """
    This function is adapted for Render.com.
    Instead of UDP broadcast, it connects to explicitly configured peers.
    Peers are specified via the PEER_NODES environment variable.
    """
    peer_urls_str = os.environ.get("PEER_NODES", "")
    peers_to_connect = [p.strip().split(':', 1) for p in peer_urls_str.split(',') if ':' in p]

    for peer_id, peer_url_with_protocol in peers_to_connect:
        if peer_id == current_node_id:
            continue # Do not connect to self

        try:
            if not peer_url_with_protocol.startswith("wss://"):
                peer_url_with_protocol = f"wss://{peer_url_with_protocol}"
            
            from urllib.parse import urlparse
            parsed_url = urlparse(peer_url_with_protocol)
            peer_host = parsed_url.hostname
            peer_port = parsed_url.port or 443 # Default to 443 for wss if not specified

            logging.info(f"[NODE_DISCOVERY] Đang cố gắng kết nối tới peer {peer_id} tại {peer_host}:{peer_port}")
            await node.connect_to_peer(peer_host, peer_port, peer_id)
        except Exception as e:
            logging.error(f"[NODE_DISCOVERY] ❌ Lỗi khi kết nối tới peer {peer_id} ({peer_url_with_protocol}): {e}")

    while True:
        await asyncio.sleep(60) # Sleep for 1 minute


async def main():
    # Read configuration from environment variables for Render.com deployment
    node_id = os.environ.get("NODE_ID", "default_node_id_0").strip()
    
    # FIX: Ensure shard_id, node_port are converted safely from string to int
    shard_id_str = os.environ.get("SHARD_ID", "0").strip()
    shard_id = int(shard_id_str) if shard_id_str.isdigit() else 0 # Default to 0 if not a digit

    # Render.com provides the PORT environment variable for web services.
    node_port_str = os.environ.get("PORT", "8000").strip()
    node_port = int(node_port_str) if node_port_str.isdigit() else 8000 # Default to 8000 if not a digit

    node_host = os.environ.get("HOST", "0.0.0.0").strip()

    is_validator_str = os.environ.get("IS_VALIDATOR", "True").strip().lower()
    is_validator = is_validator_str == "true"

    all_validator_ids_str = os.environ.get("ALL_VALIDATOR_IDS", f"{node_id}").strip()
    all_validator_ids = [v.strip() for v in all_validator_ids_str.split(',') if v.strip()]
    all_validator_ids.sort() # Keep sorted for consistency

    logging.info(f"Khởi tạo Node với các thông số:")
    logging.info(f"  Node ID: {node_id}")
    logging.info(f"  Shard ID: {shard_id}")
    logging.info(f"  Port: {node_port}")
    logging.info(f"  Host: {node_host}")
    logging.info(f"  Is Validator: {is_validator}")
    logging.info(f"  All Validator IDs: {all_validator_ids}")

    # Load or generate TLS certificates for the node
    private_key_pem_tls, certificate_pem_tls, ssl_server_ctx, ssl_client_ctx = \
        load_or_generate_tls_certs(node_id, node_host, all_validator_ids)

    # Initialize the blockchain
    blockchain = VietIDBlockchain(node_id, shard_id)

    SHARD_VALIDATOR_MAP = {
        0: ["node_1_id_example_for_dbft"],
        1: ["node_2_id_example_for_dbft"],
        2: ["node_3_id_example_for_dbft"]
    }
    validators_for_shard = SHARD_VALIDATOR_MAP.get(shard_id, [])
    validators = validators_for_shard

    blockchain.validator_shards = SHARD_VALIDATOR_MAP

    # Load or generate wallet
    wallet_dir = os.path.join(os.getcwd(), f"node_data_{node_id}")
    os.makedirs(wallet_dir, exist_ok=True)
    wallet_file = os.path.join(wallet_dir, f"wallet_{node_id}.json")

    if os.path.exists(wallet_file):
        with open(wallet_file, 'r') as f:
            wallet_data = json.load(f)
        private_key_pem = wallet_data.get("private_key_pem", "").encode("utf-8")
        sender_wallet = Wallet(private_key_pem=private_key_pem)
        logging.info(f"✅ Đã tải ví từ: {wallet_file}")
    else:
        sender_wallet = Wallet()
        with open(wallet_file, 'w') as f:
            json.dump({
                "private_key_pem": sender_wallet.private_key_pem.decode('utf-8'),
                "public_key_pem": sender_wallet.public_key_pem.decode('utf-8'),
                "alias": sender_wallet.alias,
                "address": sender_wallet.address
            }, f, indent=4)
        logging.info(f"✅ Ví mới đã được tạo và lưu tại: {wallet_file}")
    logging.info(f"Ví đã được tạo. Địa chỉ: {sender_wallet.address}")

    # Initialize P2PNode
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

    # Initialize D-BFT Consensus
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

    # Start Flask API server in a separate thread.
    threading.Thread(target=run_api, args=(blockchain, node, sender_wallet), daemon=True).start()
    logging.info("Flask API server đã được khởi động trong một luồng riêng.")

    # Call broadcast_node_info once for logging purposes (original loop removed)
    broadcast_node_info(node_id, node_host, node_port)

    # Start main asyncio tasks: P2P server, Consensus loop, and Node discovery (peer connection).
    tasks = [
        asyncio.create_task(node.run_server()),
        asyncio.create_task(consensus.run_consensus_loop()),
        asyncio.create_task(listen_for_nodes(node_id, node))
    ]

    try:
        await asyncio.gather(*tasks)
    except Exception as e:
        logging.error(f"[Main] ❌ Lỗi khi chạy node: {e}", exc_info=True)
    except KeyboardInterrupt:
        logging.info("[Main] ❗ Dừng bởi người dùng.")
    finally:
        logging.info("[Main] 🔻 Dọn dẹp node...")
        if node.server:
            node.server.close()
            await node.server.wait_closed()
            logging.info("P2P Server đã đóng.")
        if node.message_processor_task:
            node.message_processor_task.cancel()
            try:
                await node.message_processor_task
            except asyncio.CancelledError:
                logging.info("Message processor task đã bị hủy.")
            except Exception as e:
                logging.error(f"Lỗi khi hủy message processor task: {e}")
        if consensus.consensus_loop_task:
            consensus.consensus_loop_task.cancel()
            try:
                await consensus.consensus_loop_task
            except asyncio.CancelledError:
                logging.info("Consensus loop task đã bị hủy.")
            except Exception as e:
                logging.error(f"Lỗi khi hủy consensus loop task: {e}")
        logging.info("[Main] ▲ Node đã dừng hoàn toàn.")
        sys.exit(0)

if __name__ == "__main__":
    asyncio.run(main())

"
I have selected the code between `` and `` in the most up-to-date Canvas "run_node.py (Render.com Compatible)" document above.

I noticed an error in the latest deployment logs: `AttributeError: module 'ipaddress' has no attribute 'IPv44Address'. Did you mean: 'IPv4Address'?`
Could you please correct this typo in the selected code?Tôi nhận thấy lỗi `AttributeError` trong nhật ký triển khai của bạn. Đó là một lỗi đánh máy nhỏ. Tôi sẽ cập nhật Canvas `run_node.py (Render.com Compatible)` để sửa lỗi `IPv44Address` thành `IPv4Address`.


```python
import asyncio, os, json, ipaddress, ssl, socket, threading, time
import sys # Import sys to allow clean exit
import logging # Import logging module
try:
    import requests # Required for fetching peer certificates via HTTP(S)
except ImportError:
    logging.warning("Requests library not found. Cert fetching from external peers might fail.")
    requests = None # Set to None and handle gracefully

from datetime import datetime, timedelta, timezone
from vietid17 import VietIDBlockchain, Wallet, Transaction, D_BFT_Consensus, hash_message, schnorr_sign
from p2p_node import P2PNode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from api_server import run_api

# Configure basic logging for visibility on Render.com
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_rsa_key_pair():
    """Generates a new RSA private and public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_self_signed_cert(private_key, public_key, common_name, host_ip, validity_days=365):
    """Generates a self-signed X.509 certificate."""
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
            # Add DNSName for cloud environments where hostnames are common,
            # alongside IPAddress for robustness.
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.IPAddress(ipaddress.ip_address(host_ip))
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    return cert

def load_or_generate_tls_certs(current_node_id: str, host_ip: str, all_validator_ids: list):
    """
    Loads or generates TLS certificates for the current node and sets up SSL contexts.
    Attempts to fetch certificates from other peers if configured.
    """
    data_dir = os.path.join(os.getcwd(), f"node_data_{current_node_id}")
    os.makedirs(data_dir, exist_ok=True)
    logging.info(f"Đảm bảo thư mục dữ liệu nút tồn tại: {data_dir}")

    key_path = os.path.join(data_dir, f"{current_node_id}_key.pem")
    cert_path = os.path.join(data_dir, f"{current_node_id}.pem")

    logging.warning("Tạo chứng chỉ tự ký mới cho nút (Render có thể reset filesystem).")
    private_key, public_key = generate_rsa_key_pair()
    common_name = f"{current_node_id}.vietid.blockchain" # Use node_id as common name for cert

    # FIX: Corrected typo from IPv44Address to IPv4Address
    host_ip_for_cert = ipaddress.IPv4Address("127.0.0.1")

    certificate = generate_self_signed_cert(private_key, public_key, common_name, str(host_ip_for_cert))
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
    logging.info(f"Đã tạo chứng chỉ và khóa mới tại: {cert_path}, {key_path}")

    # Initialize SSLContexts
    ssl_context_server = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context_server.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ssl_context_server.verify_mode = ssl.CERT_REQUIRED
    ssl_context_server.check_hostname = False # Disable hostname check for self-signed/internal usage

    ssl_context_client = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context_client.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ssl_context_client.verify_mode = ssl.CERT_REQUIRED
    ssl_context_client.check_hostname = False # Disable hostname check for self-signed/internal usage

    # Fetch and load certificates from other validators, if configured via environment variables.
    # This assumes other validators expose their cert via a public URL (e.g., /cert endpoint).
    peer_cert_urls_str = os.environ.get("PEER_CERT_URLS", "")
    peer_cert_urls = [url.strip() for url in peer_cert_urls_str.split(',') if url.strip()]

    for peer_cert_url in peer_cert_urls:
        if requests: # Only attempt if 'requests' library is available
            try:
                logging.info(f"[TLS] 📡 Đang cố gắng tải cert từ URL: {peer_cert_url}")
                resp = requests.get(peer_cert_url, verify=False, timeout=5)
                resp.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
                
                temp_peer_cert_file = os.path.join(data_dir, f"temp_peer_{hash(peer_cert_url)}.pem")
                with open(temp_peer_cert_file, "w") as f:
                    f.write(resp.text)
                
                ssl_context_server.load_verify_locations(cafile=temp_peer_cert_file)
                ssl_context_client.load_verify_locations(cafile=temp_peer_cert_file)
                logging.info(f"[TLS] ✅ Đã tải và thêm chứng chỉ từ {peer_cert_url}.")
                os.remove(temp_peer_cert_file) # Clean up temporary file
            except requests.exceptions.RequestException as e:
                logging.error(f"[TLS] ❌ Lỗi khi tải cert từ {peer_cert_url}: {e}")
            except Exception as e:
                logging.error(f"[TLS] ❌ Lỗi không xác định khi xử lý cert từ {peer_cert_url}: {e}")
        else:
            logging.warning(f"[TLS] ⚠️ Requests library không có. Không thể tải chứng chỉ từ {peer_cert_url}.")

    logging.info("✅ SSLContext đã được cấu hình thành công.")
    return private_key_pem, certificate_pem, ssl_context_server, ssl_context_client


def broadcast_node_info(node_id, host, port):
    """
    This function is adapted for Render.com.
    UDP broadcast (255.255.255.255) typically does not work across instances in cloud environments.
    This function now primarily serves for logging the node's startup information.
    The original continuous loop for broadcasting is removed.
    """
    logging.info(f"[NODE_INFO] Node {node_id} đang hoạt động tại {host}:{port}")


async def listen_for_nodes(current_node_id, node: P2PNode):
    """
    This function is adapted for Render.com.
    Instead of UDP broadcast, it connects to explicitly configured peers.
    Peers are specified via the PEER_NODES environment variable.
    """
    peer_urls_str = os.environ.get("PEER_NODES", "")
    peers_to_connect = [p.strip().split(':', 1) for p in peer_urls_str.split(',') if ':' in p]

    for peer_id, peer_url_with_protocol in peers_to_connect:
        if peer_id == current_node_id:
            continue # Do not connect to self

        try:
            if not peer_url_with_protocol.startswith("wss://"):
                peer_url_with_protocol = f"wss://{peer_url_with_protocol}"
            
            from urllib.parse import urlparse
            parsed_url = urlparse(peer_url_with_protocol)
            peer_host = parsed_url.hostname
            peer_port = parsed_url.port or 443 # Default to 443 for wss if not specified

            logging.info(f"[NODE_DISCOVERY] Đang cố gắng kết nối tới peer {peer_id} tại {peer_host}:{peer_port}")
            await node.connect_to_peer(peer_host, peer_port, peer_id)
        except Exception as e:
            logging.error(f"[NODE_DISCOVERY] ❌ Lỗi khi kết nối tới peer {peer_id} ({peer_url_with_protocol}): {e}")

    while True:
        await asyncio.sleep(60) # Sleep for 1 minute


async def main():
    # Read configuration from environment variables for Render.com deployment
    node_id = os.environ.get("NODE_ID", "default_node_id_0").strip()
    
    # FIX: Ensure shard_id, node_port are converted safely from string to int
    shard_id_str = os.environ.get("SHARD_ID", "0").strip()
    shard_id = int(shard_id_str) if shard_id_str.isdigit() else 0 # Default to 0 if not a digit

    # Render.com provides the PORT environment variable for web services.
    node_port_str = os.environ.get("PORT", "8000").strip()
    node_port = int(node_port_str) if node_port_str.isdigit() else 8000 # Default to 8000 if not a digit

    node_host = os.environ.get("HOST", "0.0.0.0").strip()

    is_validator_str = os.environ.get("IS_VALIDATOR", "True").strip().lower()
    is_validator = is_validator_str == "true"

    all_validator_ids_str = os.environ.get("ALL_VALIDATOR_IDS", f"{node_id}").strip()
    all_validator_ids = [v.strip() for v in all_validator_ids_str.split(',') if v.strip()]
    all_validator_ids.sort() # Keep sorted for consistency

    logging.info(f"Khởi tạo Node với các thông số:")
    logging.info(f"  Node ID: {node_id}")
    logging.info(f"  Shard ID: {shard_id}")
    logging.info(f"  Port: {node_port}")
    logging.info(f"  Host: {node_host}")
    logging.info(f"  Is Validator: {is_validator}")
    logging.info(f"  All Validator IDs: {all_validator_ids}")

    # Load or generate TLS certificates for the node
    private_key_pem_tls, certificate_pem_tls, ssl_server_ctx, ssl_client_ctx = \
        load_or_generate_tls_certs(node_id, node_host, all_validator_ids)

    # Initialize the blockchain
    blockchain = VietIDBlockchain(node_id, shard_id)

    SHARD_VALIDATOR_MAP = {
        0: ["node_1_id_example_for_dbft"],
        1: ["node_2_id_example_for_dbft"],
        2: ["node_3_id_example_for_dbft"]
    }
    validators_for_shard = SHARD_VALIDATOR_MAP.get(shard_id, [])
    validators = validators_for_shard

    blockchain.validator_shards = SHARD_VALIDATOR_MAP

    # Load or generate wallet
    wallet_dir = os.path.join(os.getcwd(), f"node_data_{node_id}")
    os.makedirs(wallet_dir, exist_ok=True)
    wallet_file = os.path.join(wallet_dir, f"wallet_{node_id}.json")

    if os.path.exists(wallet_file):
        with open(wallet_file, 'r') as f:
            wallet_data = json.load(f)
        private_key_pem = wallet_data.get("private_key_pem", "").encode("utf-8")
        sender_wallet = Wallet(private_key_pem=private_key_pem)
        logging.info(f"✅ Đã tải ví từ: {wallet_file}")
    else:
        sender_wallet = Wallet()
        with open(wallet_file, 'w') as f:
            json.dump({
                "private_key_pem": sender_wallet.private_key_pem.decode('utf-8'),
                "public_key_pem": sender_wallet.public_key_pem.decode('utf-8'),
                "alias": sender_wallet.alias,
                "address": sender_wallet.address
            }, f, indent=4)
        logging.info(f"✅ Ví mới đã được tạo và lưu tại: {wallet_file}")
    logging.info(f"Ví đã được tạo. Địa chỉ: {sender_wallet.address}")

    # Initialize P2PNode
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

    # Initialize D-BFT Consensus
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

    # Start Flask API server in a separate thread.
    threading.Thread(target=run_api, args=(blockchain, node, sender_wallet), daemon=True).start()
    logging.info("Flask API server đã được khởi động trong một luồng riêng.")

    # Call broadcast_node_info once for logging purposes (original loop removed)
    broadcast_node_info(node_id, node_host, node_port)

    # Start main asyncio tasks: P2P server, Consensus loop, and Node discovery (peer connection).
    tasks = [
        asyncio.create_task(node.run_server()),
        asyncio.create_task(consensus.run_consensus_loop()),
        asyncio.create_task(listen_for_nodes(node_id, node))
    ]

    try:
        await asyncio.gather(*tasks)
    except Exception as e:
        logging.error(f"[Main] ❌ Lỗi khi chạy node: {e}", exc_info=True)
    except KeyboardInterrupt:
        logging.info("[Main] ❗ Dừng bởi người dùng.")
    finally:
        logging.info("[Main] 🔻 Dọn dẹp node...")
        if node.server:
            node.server.close()
            await node.server.wait_closed()
            logging.info("P2P Server đã đóng.")
        if node.message_processor_task:
            node.message_processor_task.cancel()
            try:
                await node.message_processor_task
            except asyncio.CancelledError:
                logging.info("Message processor task đã bị hủy.")
            except Exception as e:
                logging.error(f"Lỗi khi hủy message processor task: {e}")
        if consensus.consensus_loop_task:
            consensus.consensus_loop_task.cancel()
            try:
                await consensus.consensus_loop_task
            except asyncio.CancelledError:
                logging.info("Consensus loop task đã bị hủy.")
            except Exception as e:
                logging.error(f"Lỗi khi hủy consensus loop task: {e}")
        logging.info("[Main] ▲ Node đã dừng hoàn toàn.")
        sys.exit(0)

if __name__ == "__main__":
    asyncio.run(main())

