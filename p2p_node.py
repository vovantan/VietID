import asyncio, websockets, json
from vietid17 import Transaction

def get_shard_for_node_id(node_id):
        # Mapping giả định
    return {
        "node1": 0,
        "node2": 1,
        "node3": 2,
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

    async def run_server(self):
        self.server = await websockets.serve(
            self.handle_peer,
            self.host,
            self.port,
            ssl=self.ssl_context_server
        )
        print(f"[P2P] Node {self.node_id[:10]}... đang lắng nghe tại wss://{self.host}:{self.port}")
        await self.server.wait_closed()

    async def connect_to_peer(self, host, current_node_id):
            uri = f"wss://{host}/ws/{current_node_id}"
            try:
                async with websockets.connect(uri, ssl=self.ssl_context_client) as websocket:
                    await websocket.send(current_node_id)
                    peer_id = await websocket.recv()
                    self.peers[peer_id] = websocket
                    print(f"[P2P] ✅ Đã kết nối đến {uri} (Peer: {peer_id})")
        
                    async for msg in websocket:
                        await self.message_queue.put((peer_id, msg))
        
            except Exception as e:
                print(f"[P2P] ❌ Kết nối đến {uri} thất bại: {e}")



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
        finally:
            if peer_id and peer_id in self.peers:
                del self.peers[peer_id]
                print(f"[P2P] 🔌 Peer {peer_id} đã ngắt kết nối")

    async def broadcast_message(self, message: dict):
        # Nếu là CONSENSUS → kiểm tra shard và quyền validator
        if message.get("type") == "CONSENSUS":
            # Lấy shard ID hiện tại của node gửi (self)
            my_shard = get_shard_for_node_id(self.node_id)
            # Danh sách validator hợp lệ của shard hiện tại
            valid_validator_ids = self.blockchain.get_validator_ids_for_shard(my_shard)

            # Nếu self không phải validator → không được gửi CONSENSUS
            if self.node_id not in valid_validator_ids:
                print(f"[P2P][FILTER] ❌ Không phải validator → chặn gửi CONSENSUS")
                return

            # Gửi CONSENSUS chỉ đến các peer cùng shard và là validator
            for peer_id, websocket in self.peers.items():
                peer_shard = get_shard_for_node_id(peer_id)
                if peer_shard != my_shard:
                    continue  # ❌ khác shard
                if peer_id not in valid_validator_ids:
                    continue  # ❌ peer không phải validator

                try:
                    await websocket.send(json.dumps(message))
                    print(f"[P2P][SEND] ✅ Gửi CONSENSUS {message.get('subtype')} tới validator {peer_id}")
                except Exception as e:
                    print(f"[P2P] ❌ Gửi CONSENSUS tới {peer_id} thất bại: {e}")
            return  # Không gửi lặp lại bên dưới

        if message.get("type") == "TRANSACTION":
            tx_type = message["transaction"].get("tx_type")

            if tx_type == "CROSS_TRANSFER":
                # ❌ Không broadcast CROSS_TRANSFER ra ngoài – chỉ xử lý nội bộ shard
                my_shard = get_shard_for_node_id(self.node_id)
                print(f"[P2P][FILTER] ⛔ Giao dịch CROSS_TRANSFER chỉ xử lý trong shard nguồn ({my_shard}), không broadcast.")
                return
            
        dead_peers = []
        for peer_id, websocket in self.peers.items():
            try:
                await websocket.send(json.dumps(message))
            except Exception as e:
                print(f"[P2P] ❌ Gửi tin nhắn tới peer {peer_id} thất bại: {e}")
                dead_peers.append(peer_id)
        for peer_id in dead_peers:
            del self.peers[peer_id]


    async def _process_message_queue(self):
        try:
            while True:
                peer_id, raw_message = await self.message_queue.get()
                print(f"[P2P] 📩 Nhận raw message từ {peer_id}: {raw_message[:50]}...")  # In giới hạn độ dài

                try:
                    msg = json.loads(raw_message)
                except json.JSONDecodeError:
                    print("[P2P] ❌ Lỗi giải mã JSON.")
                    continue

                msg_type = msg.get("type")

                if msg_type == "TRANSACTION":
                    tx_data = msg.get("transaction")
                    if not tx_data:
                        print("[P2P] ❌ Message TRANSACTION thiếu dữ liệu.")
                        continue

                    print(f"[P2P] 📥 Nhận TRANSACTION từ {peer_id}: {tx_data.get('txid', '')[:10]}... loại: {tx_data.get('tx_type')}")

                    try:
                        # KHÔNG chuyển đổi thủ công public_key hay signature ở đây!
                        tx = Transaction.from_dict(tx_data)
                        print(f"[DEBUG] ✅ Transaction object khởi tạo: {tx.txid[:10]}... loại: {tx.tx_type}")

                        if tx.tx_type == "RECEIVE_TRANSFER":
                            added = self.blockchain.add_transaction_to_mempool(tx)
                            print(f"[P2P] ✅ Đã thêm RECEIVE_TRANSFER {tx.txid[:10]}... vào mempool: {added}")
                        elif tx.is_valid():
                            added = self.blockchain.add_transaction_to_mempool(tx)
                            print(f"[P2P] ✅ Thêm giao dịch hợp lệ {tx.txid[:10]}... vào mempool: {added}")
                        else:
                            print(f"[P2P] ❌ Giao dịch không hợp lệ: {tx.txid[:10]}...")

                    except Exception as e:
                        print(f"[P2P] ❌ Lỗi khởi tạo Transaction: {e}")
                        continue

                elif msg_type == "BLOCK":
                    block_data = msg.get("block")
                    if block_data:
                        print(f"[P2P] 📥 Nhận BLOCK {block_data.get('hash', '')[:10]}... từ {peer_id}")
                        block = Block.from_dict(block_data)
                        if self.blockchain.add_block(block):
                            print(f"[P2P] ✅ Đã thêm block {block.hash[:10]}... từ {peer_id} vào chuỗi.")
                        else:
                            print(f"[P2P] ❌ Không thể thêm block {block.hash[:10]}... từ {peer_id}.")

                elif msg.get("type") == "CONSENSUS":
                    if self.consensus:
                        subtype = msg.get("subtype")
                        if subtype == "PRE_PREPARE":
                            await self.consensus.handle_pre_prepare(msg)
                        elif subtype == "PREPARE":
                            await self.consensus.handle_prepare(msg)
                        elif subtype == "COMMIT":
                            await self.consensus.handle_commit(msg)
                        else:
                            print(f"[P2P] ⚠️ CONSENSUS subtype không xác định: {subtype}")
                    else:
                        print(f"[P2P] ⚠️ CONSENSUS message nhận được nhưng không có self.consensus.")


                elif msg_type == "REQUEST_LATEST_BLOCK":
                    latest_block = self.blockchain.get_latest_block()
                    if latest_block:
                        await self.send_to_peer(peer_id, {
                            "type": "LATEST_BLOCK_RESPONSE",
                            "block": latest_block.to_dict()
                        })
                        print(f"[P2P] ⬆️ Đã gửi LATEST_BLOCK_RESPONSE cho {peer_id}")

                elif msg_type == "LATEST_BLOCK_RESPONSE":
                    block_data = msg.get("block")
                    if block_data:
                        block = Block.from_dict(block_data)
                        if block.index > self.blockchain.get_latest_block().index:
                            if self.blockchain.add_block(block):
                                print(f"[P2P] ✅ Đã thêm block mới nhất {block.hash[:10]}... từ LATEST_BLOCK_RESPONSE.")
                            else:
                                print(f"[P2P] ❌ Không thể thêm block mới nhất {block.hash[:10]}... từ LATEST_BLOCK_RESPONSE.")
                        else:
                            print(f"[P2P] ℹ️ Block nhận được từ LATEST_BLOCK_RESPONSE không mới hơn.")

                else:
                    print(f"[P2P] ℹ️ Nhận message không xác định từ {peer_id}: {msg_type}")

        except asyncio.CancelledError:
            print("[P2P_QUEUE] Message processing queue cancelled. Shutting down.")
        except Exception as e:
            print(f"[P2P_QUEUE] ❌ Lỗi trong vòng lặp xử lý message: {e}")
            import traceback
            traceback.print_exc()

    async def send_to_shard(self, message: dict, target_shard: int):
        print(f"[P2P] Đang cố gắng gửi tin nhắn tới shard {target_shard}")
        message_json = json.dumps(message)
        sent_to_any_peer_in_shard = False
        for peer_id, ws in self.peers.items():
            peer_shard_id = get_shard_for_node_id(peer_id) # Sử dụng hàm helper
            if peer_shard_id == target_shard:
                try:
                    await ws.send(message_json)
                    print(f"[P2P] ✅ Đã gửi tin nhắn {message['type']}/{message.get('subtype', '')} tới peer {peer_id} (shard {peer_shard_id}).")
                    sent_to_any_peer_in_shard = True
                except websockets.exceptions.ConnectionClosed:
                    print(f"[P2P] ⚠️ Kết nối tới peer {peer_id} đã đóng. Xóa khỏi danh sách.")
                    del self.peers[peer_id]
                except Exception as e:
                    print(f"[P2P] ❌ Lỗi gửi tin nhắn tới peer {peer_id}: {e}")
        if not sent_to_any_peer_in_shard:
            print(f"[P2P] ⚠️ Không tìm thấy peer nào trong shard {target_shard} để gửi tin nhắn.")
