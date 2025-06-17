from vietid17 import Transaction, Wallet, hash_message, schnorr_sign, StateDB
#from flask import Flask, jsonify, request, send_file
from quart import Quart, request, jsonify, websocket, send_file
from datetime import datetime, timezone
import logging, os, json, asyncio, traceback

app = Quart(__name__)

# Biến toàn cục
blockchain = None
p2p_node = None
wallet = None

@app.route("/cert/<node_id>", methods=["GET"])
async def get_certificate(node_id):
    cert_path = os.path.join(os.getcwd(), f"node_data_{node_id}", f"{node_id}.pem")
    if os.path.exists(cert_path):
        return await send_file(cert_path, mimetype="application/x-pem-file")
    return jsonify({"error": "Certificate not found"}), 404


@app.route('/status', methods=['GET'])
async def status():
    return jsonify({
        "node_id": blockchain.node_id,
        "shard_id": blockchain.shard_id,
        "chain_length": len(blockchain.chain),
        "mempool_size": len(blockchain.mempool)
    })

@app.route('/block/latest', methods=['GET'])
async def get_latest_block():
    latest = blockchain.get_latest_block()
    return jsonify(latest.to_dict())

@app.route('/blocks/recent/<int:count>', methods=['GET'])
async def get_recent_blocks(count):
    recent = blockchain.chain[-count:]
    return jsonify([block.to_dict() for block in reversed(recent)])

@app.route('/block/<identifier>', methods=['GET'])
async def get_block_by_identifier(identifier):
    for block in blockchain.chain:
        # So sánh cả dạng int và string
        if block.hash == identifier:
            return jsonify(block.to_dict())
        try:
            if block.index == int(identifier):
                return jsonify(block.to_dict())
        except ValueError:
            continue
    return jsonify({"error": "Block not found"}), 404


@app.route('/balance/<address>', methods=['GET'])
async def get_balance(address):
    balance = blockchain.state_db.get_balance(address)
    return jsonify({"address": address, "balance": balance})

@app.route('/did/list', methods=['GET'])
def get_did_list():
    safe_registry = {}
    for did, data in blockchain.state_db.did_registry.items():
        safe_registry[did] = {
            "alias": data.get("alias"),
            "public_key_tuple": list(data.get("public_key_tuple", [])),
            "public_key_bytes": data.get("public_key_bytes").hex() if isinstance(data.get("public_key_bytes"), bytes) else data.get("public_key_bytes")
        }
    return jsonify(safe_registry)


@app.route('/did/<did>', methods=['GET'])
def get_did_info(did):
    data = blockchain.state_db.did_registry.get(did)
    if data:
        return jsonify({
            "alias": data.get("alias"),
            "public_key_tuple": list(data.get("public_key_tuple", [])),
            "public_key_bytes": data.get("public_key_bytes").hex() if isinstance(data.get("public_key_bytes"), bytes) else data.get("public_key_bytes")
        })
    return jsonify({"error": "DID not found"}), 404

@app.route('/mempool', methods=['GET'])
async def get_mempool():
    mempool_data = []
    for tx in blockchain.mempool:
        if hasattr(tx, 'to_dict'):
            mempool_data.append(tx.to_dict())
        elif isinstance(tx, str):
            try:
                mempool_data.append(json.loads(tx))
            except Exception:
                mempool_data.append({"error": "invalid format", "raw": tx})
        else:
            mempool_data.append({"error": "unknown tx type", "raw": str(tx)})
    return jsonify(mempool_data)


@app.route('/tx/<txid>', methods=['GET'])
async def get_transaction_by_txid(txid):
    for block in blockchain.chain:
        for tx in block.transactions:
            if tx.txid == txid:
                return jsonify(tx.to_dict())
    return jsonify({"error": "Transaction not found"}), 404

@app.route('/governance/proposals', methods=['GET'])
async def get_governance_proposals():
    # Chuyển tất cả set thành list để JSON hóa
    safe_data = {
        k: {kk: list(vv) if isinstance(vv, set) else vv for kk, vv in v.items()}
        for k, v in blockchain.state_db.governance_proposals.items()
    }
    return jsonify(safe_data)

@app.route('/governance/proposal/<proposal_id>', methods=['GET'])
async def get_governance_proposal(proposal_id):
    proposal = blockchain.state_db.governance_proposals.get(proposal_id)
    if proposal:
        # Convert the 'voters' set to a list before jsonify-ing
        # Create a copy to avoid modifying the original state directly if not intended
        serializable_proposal = proposal.copy()
        if "voters" in serializable_proposal and isinstance(serializable_proposal["voters"], set):
            serializable_proposal["voters"] = list(serializable_proposal["voters"])
        return jsonify(serializable_proposal) # <--- Pass the serializable_proposal here
    return jsonify({"error": f"proposal_id {proposal_id} not found"}), 404

# In api_server.py, find the get_governance_votes route:

@app.route('/governance/votes/<proposal_id>', methods=['GET'])
async def get_governance_votes(proposal_id):
    proposal = blockchain.state_db.governance_proposals.get(proposal_id)
    if proposal:
        # Correctly access votes_for and votes_against directly
        return jsonify({
            "proposal_id": proposal_id,
            "votes_for": proposal.get("votes_for", 0),      # <--- CHANGE THIS LINE
            "votes_against": proposal.get("votes_against", 0) # <--- CHANGE THIS LINE
        })
    return jsonify({"error": f"proposal_id {proposal_id} not found"}), 404

@app.route('/tx/send', methods=['POST'])
async def send_transaction():
    try:
        data = await request.get_json()

        recipient = data["recipient"]
        amount = int(data["amount"])
        # Xác định recipient_public_key_bytes từ recipient (có thể là pubkey hoặc address)
        recipient_public_key_bytes = None

        if len(recipient) in (66, 130):  # public key hex (compressed/uncompressed)
            recipient_public_key_bytes = bytes.fromhex(recipient)
        elif len(recipient) == 40:  # address dạng hex
            recipient_pubkey = blockchain.state_db.get_pubkey_by_address(recipient)
            if not recipient_pubkey:
                return jsonify({
                    "status": "error",
                    "message": f"Cannot resolve address {recipient} to public key"
                }), 400
            recipient_public_key_bytes = recipient_pubkey
        else:
            return jsonify({"status": "error", "message": "Invalid recipient format"}), 400

        tx = Transaction(
            sender_public_key_bytes=wallet.public_key_raw_bytes,
            #recipient_public_key_bytes=bytes.fromhex(recipient),
            recipient_public_key_bytes=recipient_public_key_bytes,
            amount=amount,
            tx_type="TRANSFER",
            data=""
        )
        tx_hash = hash_message(tx.to_string_for_signing().encode('utf-8'))
        tx.signature = schnorr_sign(wallet.private_key_ecc, tx_hash)

        if blockchain.add_transaction_to_mempool(tx):
            await p2p_node.broadcast_message({
                "type": "TRANSACTION",
                "transaction": tx.to_dict()
            })

            return jsonify({"status": "success", "txid": tx.txid})
        else:
            return jsonify({"status": "failed", "reason": "Invalid or duplicate transaction"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/tx/send/<tx_type>', methods=['POST'])
async def send_special_tx(tx_type):
    try:
        data = await request.get_json()
        tx = None

        if tx_type == "DID":
            alias = data.get("alias", "Anonymous")
            did = f"did:vietid:{wallet.public_key_raw_bytes.hex()}"
            tx = Transaction(
                sender_public_key_bytes=wallet.public_key_raw_bytes,
                recipient_public_key_bytes=b'',
                amount=0,
                tx_type="DID_REGISTER",
                data=json.dumps({
                    "did": did,
                    "public_key_tuple": wallet.public_key_tuple,
                    "alias": alias
                })
            )
        elif tx_type == "VOTE":
            tx = Transaction(
                sender_public_key_bytes=wallet.public_key_raw_bytes,
                recipient_public_key_bytes=b'',
                amount=0,
                tx_type="VOTE",
                data=json.dumps({
                    "proposal_id": data["proposal_id"],
                    "vote": data["vote"]
                })
            )
        elif tx_type == "MINT":
            recipient = data["recipient"]
            amount = int(data["amount"])
            tx = Transaction(
                sender_public_key_bytes=wallet.public_key_raw_bytes,
                recipient_public_key_bytes=bytes.fromhex(recipient),
                amount=amount,
                tx_type="MINT",
                data=json.dumps({   # ✅ Truyền đầy đủ JSON data
                    "recipient": recipient,
                    "amount": amount
                })
            )
        
        
        elif tx_type == "PROPOSE":
            proposal_id = data["proposal_id"]
            description = data["description"]
            title = data.get("title", "")  # lấy nếu có
            tx = Transaction(
                sender_public_key_bytes=wallet.public_key_raw_bytes,
                recipient_public_key_bytes=b"",  # để trống nếu không cần nhận
                amount=0,
                #tx_type="PROPOSE",
                tx_type="GOVERNANCE_PROPOSAL",
                data=json.dumps({
                    "proposal_id": proposal_id,
                    "title": title,
                    "description": description
                })
            )

        else:
            return jsonify({"error": f"Transaction type '{tx_type}' not supported"}), 400

        tx.signature = schnorr_sign(wallet.private_key_ecc, hash_message(tx.to_string_for_signing().encode()))
        
        if blockchain.add_transaction_to_mempool(tx):
            await p2p_node.broadcast_message({
                "type": "TRANSACTION",
                "transaction": tx.to_dict()
            })
            return jsonify({"status": "success", "txid": tx.txid})
        
        else:
            return jsonify({"status": "failed", "reason": "Transaction invalid or exists"}), 400
        
    except Exception as e:
        print(f"An error occurred: {e}") # New log
        traceback.print_exc() # New log to print the full traceback
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/tx/send/CROSS_TRANSFER', methods=['POST'])
async def send_cross_transfer():
    try:

        data = await request.get_json()

        print(f"[DEBUG] Nhận CROSS_TRANSFER: from {data.get('from_shard')} → {data.get('to_shard')}")
        from_shard = data["from_shard"]
        to_shard = data["to_shard"]
        recipient_address = data["recipient_address"]
        amount = int(data["amount"])
        print("[DEBUG] API request.json:", data)
        print(f"[DEBUG] API extracted from_shard: {from_shard}, to_shard: {to_shard}, recipient: {recipient_address}, amount: {amount}")

        # Tạo giao dịch
        tx = Transaction(
            sender_public_key_bytes=wallet.public_key_raw_bytes,
            recipient_public_key_bytes=b'',
            amount=amount,
            tx_type="CROSS_TRANSFER",
            data=json.dumps({
                "from_shard": from_shard,
                "to_shard": to_shard,
                "recipient_address": recipient_address,
                "amount": amount
            }),
            timestamp=datetime.utcnow().isoformat() + "Z"
        )

        # Ký giao dịch
        tx_hash = hash_message(tx.to_string_for_signing().encode('utf-8'))
        tx.signature = schnorr_sign(wallet.private_key_ecc, tx_hash)

        print(f"[CROSS_TX] Giao dịch CROSS_TRANSFER được tạo: {tx.txid}")

        # Thêm vào mempool và broadcast nếu hợp lệ
        if blockchain.add_transaction_to_mempool(tx):
            await p2p_node.broadcast_message({
                "type": "TRANSACTION",
                "transaction": tx.to_dict()
            })
            return jsonify({"status": "success", "txid": tx.txid})
        else:
            return jsonify({"status": "failed", "reason": "Transaction invalid or exists"}), 400

    except Exception as e:
        print(f"[ERROR] CROSS_TRANSFER TX error: {e}")
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/", methods=["GET"])
async def index():
    return {
        "message": "VietID node is running!",
        "node_id": blockchain.node_id,
        "shard_id": blockchain.shard_id,
        "address": wallet.address
    }
@app.route("/health", methods=["GET"])
async def health():
    return jsonify({"status": "ok"}), 200

@app.route("/chain", methods=["GET"])
async def get_chain():
    return jsonify([block.to_dict() for block in blockchain.chain])


@app.websocket('/ws/<peer_id>')
async def ws(peer_id):
    await websocket.send(p2p_node.node_id)
    their_id = await websocket.receive()
    p2p_node.peers[their_id] = websocket._get_current_object()
    print(f"[WS] ✅ WebSocket kết nối từ {their_id}")

    try:
        while True:
            msg = await websocket.receive()
            await p2p_node.message_queue.put((their_id, msg))
    except Exception as e:
        print(f"[WS] ❌ Lỗi với {their_id}: {e}")
        if their_id in p2p_node.peers:
            del p2p_node.peers[their_id]
            
# Dùng để khởi tạo biến toàn cục từ run_node.py
def initialize_quart_globals(blockchain_instance, p2p_instance, wallet_instance):
    global blockchain, p2p_node, wallet
    blockchain = blockchain_instance
    p2p_node = p2p_instance
    wallet = wallet_instance

