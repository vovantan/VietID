from vietid17 import Transaction, Wallet, hash_message, schnorr_sign
from flask import Flask, jsonify, request, send_file
from datetime import datetime, timezone
import logging, os, json, asyncio, traceback

app = Flask(__name__)

# Biến toàn cục
blockchain = None
p2p_node = None
wallet = None

@app.route("/cert/<node_id>", methods=["GET"])
def get_certificate(node_id):
    cert_path = os.path.join(os.getcwd(), f"node_data_{node_id}", f"{node_id}.pem")
    if os.path.exists(cert_path):
        return send_file(cert_path, mimetype="application/x-pem-file")
    return jsonify({"error": "Certificate not found"}), 404


@app.route('/status', methods=['GET'])
def status():
    return jsonify({
        "node_id": blockchain.node_id,
        "shard_id": blockchain.shard_id,
        "chain_length": len(blockchain.chain),
        "mempool_size": len(blockchain.mempool)
    })

@app.route('/block/latest', methods=['GET'])
def get_latest_block():
    latest = blockchain.get_latest_block()
    return jsonify(latest.to_dict())

@app.route('/blocks/recent/<int:count>', methods=['GET'])
def get_recent_blocks(count):
    recent = blockchain.chain[-count:]
    return jsonify([block.to_dict() for block in reversed(recent)])

@app.route('/block/<identifier>', methods=['GET'])
def get_block_by_identifier(identifier):
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
def get_balance(address):
    balance = blockchain.state_db.get_balance(address)
    return jsonify({"address": address, "balance": balance})

@app.route('/did/list', methods=['GET'])
def get_did_list():
    return jsonify(blockchain.state_db.did_registry)

@app.route('/did/<did>', methods=['GET'])
def get_did_info(did):
    data = blockchain.state_db.did_registry.get(did)
    if data:
        return jsonify(data)
    return jsonify({"error": "DID not found"}), 404

@app.route('/mempool', methods=['GET'])
def get_mempool():
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
def get_transaction_by_txid(txid):
    for block in blockchain.chain:
        for tx in block.transactions:
            if tx.txid == txid:
                return jsonify(tx.to_dict())
    return jsonify({"error": "Transaction not found"}), 404

@app.route('/governance/proposals', methods=['GET'])
def get_governance_proposals():
    # Chuyển tất cả set thành list để JSON hóa
    safe_data = {
        k: {kk: list(vv) if isinstance(vv, set) else vv for kk, vv in v.items()}
        for k, v in blockchain.state_db.governance_proposals.items()
    }
    return jsonify(safe_data)

@app.route('/governance/proposal/<proposal_id>', methods=['GET'])
def get_governance_proposal(proposal_id):
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
def get_governance_votes(proposal_id):
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
def send_transaction():
    try:
        data = request.json
        recipient = data["recipient"]
        amount = int(data["amount"])

        tx = Transaction(
            sender_public_key_bytes=wallet.public_key_raw_bytes,
            recipient_public_key_bytes=bytes.fromhex(recipient),
            amount=amount,
            tx_type="TRANSFER",
            data=""
        )
        tx_hash = hash_message(tx.to_string_for_signing().encode('utf-8'))
        tx.signature = schnorr_sign(wallet.private_key_ecc, tx_hash)

        if blockchain.add_transaction_to_mempool(tx):
            asyncio.run(p2p_node.broadcast_message({
                "type": "TRANSACTION",
                "transaction": tx.to_dict()
            }))
            return jsonify({"status": "success", "txid": tx.txid})
        else:
            return jsonify({"status": "failed", "reason": "Invalid or duplicate transaction"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/tx/send/<tx_type>', methods=['POST'])
def send_special_tx(tx_type):
    try:
        data = request.json
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
            asyncio.run(p2p_node.broadcast_message({
                "type": "TRANSACTION",
                "transaction": tx.to_dict()
            }))
            return jsonify({"status": "success", "txid": tx.txid})
        
        else:
            return jsonify({"status": "failed", "reason": "Transaction invalid or exists"}), 400
        
    except Exception as e:
        print(f"An error occurred: {e}") # New log
        traceback.print_exc() # New log to print the full traceback
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/tx/send/CROSS_TRANSFER', methods=['POST'])
def send_cross_transfer():
    try:

        data = request.json
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
            asyncio.run(p2p_node.broadcast_message({
                "type": "TRANSACTION",
                "transaction": tx.to_dict()
            }))
            return jsonify({"status": "success", "txid": tx.txid})
        else:
            return jsonify({"status": "failed", "reason": "Transaction invalid or exists"}), 400

    except Exception as e:
        print(f"[ERROR] CROSS_TRANSFER TX error: {e}")
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/", methods=["GET"])
def index():
    return {
        "message": "VietID node is running!",
        "node_id": blockchain.node_id,
        "shard_id": blockchain.shard_id,
        "address": wallet.address
    }
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

@app.route("/chain", methods=["GET"])
def get_chain():
    return jsonify([block.to_dict() for block in blockchain.chain])


def run_api(node_instance, p2p_instance, wallet_instance):
    global blockchain, p2p_node, wallet
    blockchain = node_instance
    p2p_node = p2p_instance
    wallet = wallet_instance

    # Giảm log chi tiết của Flask
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    os.environ['FLASK_ENV'] = 'production'

    # 👇 Lấy PORT từ biến môi trường (do Render chỉ định)
    port = int(os.environ.get("PORT", 5000))

    print(f"[API] 🚀 Flask server starting at 0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)





    
    
