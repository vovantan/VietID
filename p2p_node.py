import asyncio, websockets, json, traceback
from vietid17 import Transaction

def get_shard_for_node_id(node_id):
    return {
        "node_1": 0,
        "node_2": 1,
        "node_3": 2,
    }.get(node_id, 0)

class P2PNode:
    def __init__(self, node_id, host, port, blockchain, ssl_context_server, ssl_context_client):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.blockchain = blockchain
        self.ssl_context_server = ssl_context_server
        self.ssl_context_client = ssl_context_client
        self.peers = {}  # peer_id -> websocket
        self.server = None
        self.message_queue = asyncio.Queue()
        self.message_processor_task = None
        self.consensus = None  # Ensure this exists

    async def run_server(self):
        self.server = await websockets.serve(
            self.handle_peer,
            self.host,
            self.port,
            ssl=self.ssl_context_server
        )
        print(f"[P2P] 🌐 Node {self.node_id} đang lắng nghe tại wss://{self.host}:{self.port}")
        await self.server.wait_closed()

    async def connect_to_peer(self, host, port, current_node_id):
        uri = f"wss://{host}:{port}"
        try:
            print(f"[P2P] 🔌 Đang kết nối tới {uri} từ node {self.node_id}")
            websocket = await websockets.connect(uri, ssl=self.ssl_context_client)
            await websocket.send(current_node_id)
            peer_id = await websocket.recv()
            self.peers[peer_id] = websocket
            print(f"[P2P] ✅ Đã kết nối đến {uri} (Peer: {peer_id})")
            print(f"[P2P] 🤝 Peers hiện tại của {self.node_id}: {list(self.peers.keys())}")
        except Exception as e:
            print(f"[P2P] ❌ Kết nối đến {uri} thất bại: {e}")
            traceback.print_exc()

    async def handle_peer(self, websocket, path):
        peer_id = None
        try:
            await websocket.send(self.node_id)
            peer_id = await websocket.recv()
            self.peers[peer_id] = websocket
            print(f"[P2P] ✅ Nhận kết nối từ peer {peer_id}")
            async for message in websocket:
                await self.message_queue.put((peer_id, message))
        except Exception as e:
            print(f"[P2P] ❌ Lỗi trong handle_peer: {e}")
            traceback.print_exc()
        finally:
            if peer_id and peer_id in self.peers:
                del self.peers[peer_id]
                print(f"[P2P] 🔌 Peer {peer_id} đã ngắt kết nối")

    async def broadcast_message(self, message: dict):
        if message.get("type") == "CONSENSUS":
            my_shard = get_shard_for_node_id(self.node_id)
            valid_validator_ids = self.blockchain.get_validator_ids_for_shard(my_shard)
            if self.node_id not in valid_validator_ids:
                print(f"[P2P][FILTER] ❌ Không phải validator → chặn gửi CONSENSUS")
                return

            for peer_id, websocket in self.peers.items():
                peer_shard = get_shard_for_node_id(peer_id)
                if peer_shard != my_shard:
                    continue
                if peer_id not in valid_validator_ids:
                    continue
                try:
                    await websocket.send(json.dumps(message))
                    print(f"[P2P][SEND] ✅ Gửi CONSENSUS {message.get('subtype')} tới validator {peer_id}")
                except Exception as e:
                    print(f"[P2P] ❌ Gửi CONSENSUS tới {peer_id} thất bại: {e}")
            return

        if message.get("type") == "TRANSACTION":
            tx_type = message["transaction"].get("tx_type")
            if tx_type == "CROSS_TRANSFER":
                my_shard = get_shard_for_node_id(self.node_id)
                print(f"[P2P][FILTER] ⛔ CROSS_TRANSFER chỉ xử lý trong shard ({my_shard}), không broadcast.")
                return

        dead_peers = []
        for peer_id, websocket in self.peers.items():
            try:
                await websocket.send(json.dumps(message))
                print(f"[P2P] 📤 Gửi message {message.get('type')} tới {peer_id}")
            except Exception as e:
                print(f"[P2P] ❌ Gửi tới peer {peer_id} thất bại: {e}")
                dead_peers.append(peer_id)
        for peer_id in dead_peers:
            del self.peers[peer_id]

    async def _process_message_queue(self):
        try:
            while True:
                peer_id, raw_message = await self.message_queue.get()
                print(f"[P2P] 📩 Nhận message từ {peer_id}: {raw_message[:80]}...")

                try:
                    msg = json.loads(raw_message)
                except json.JSONDecodeError:
                    print("[P2P] ❌ Lỗi JSON.")
                    continue

                msg_type = msg.get("type")

                if msg_type == "TRANSACTION":
                    tx_data = msg.get("transaction")
                    if not tx_data:
                        print("[P2P] ❌ TRANSACTION thiếu dữ liệu.")
                        continue

                    try:
                        tx = Transaction.from_dict(tx_data)
                        print(f"[P2P] ✅ Nhận TRANSACTION {tx.txid[:10]} loại {tx.tx_type}")
                        added = self.blockchain.add_transaction_to_mempool(tx)
                        print(f"[P2P] ➕ Thêm vào mempool: {added}")
                    except Exception as e:
                        print(f"[P2P] ❌ Transaction lỗi: {e}")
                        traceback.print_exc()

                elif msg_type == "CONSENSUS":
                    if self.consensus:
                        subtype = msg.get("subtype")
                        print(f"[P2P] ⚙️ Nhận CONSENSUS {subtype} từ {peer_id}")
                        if subtype == "PRE_PREPARE":
                            await self.consensus.handle_pre_prepare(msg)
                        elif subtype == "PREPARE":
                            await self.consensus.handle_prepare(msg)
                        elif subtype == "COMMIT":
                            await self.consensus.handle_commit(msg)
                        else:
                            print(f"[P2P] ⚠️ Subtype không xác định: {subtype}")
                    else:
                        print(f"[P2P] ⚠️ Nhận CONSENSUS nhưng self.consensus is None")

                else:
                    print(f"[P2P] ℹ️ Nhận message không xác định: {msg_type}")

        except asyncio.CancelledError:
            print("[P2P_QUEUE] ⏹️ Đã hủy xử lý message.")
        except Exception as e:
            print(f"[P2P_QUEUE] ❌ Lỗi xử lý queue: {e}")
            traceback.print_exc()
