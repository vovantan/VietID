from vietid17 import Transaction, Wallet, hash_message, schnorr_sign, StateDB
#from flask import Flask, jsonify, request, send_file
from quart import Quart, request, jsonify, websocket, send_file, Response
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
def status():
    return Response(
        json.dumps({
            "node_id": blockchain.node_id,
            "shard_id": blockchain.shard_id,
            "chain_length": len(blockchain.chain),
            "mempool_size": len(blockchain.mempool)
        }, indent=2),
        mimetype='application/json'
    )

@app.route('/block/latest', methods=['GET'])
def get_latest_block():
    latest = blockchain.get_latest_block()
    block_dict = latest.to_dict()
    return Response(
        json.dumps(block_dict, indent=2),  # indent đẹp
        mimetype='application/json'
    )

@app.route('/blocks/recent/<int:count>', methods=['GET'])
def get_recent_blocks(count):
    recent = blockchain.chain[-count:]
    recent_dicts = [block.to_dict() for block in recent]
    return Response(
        json.dumps(recent_dicts, indent=2),  # indent đẹp
        mimetype='application/json'
    )

@app.route('/block/<identifier>', methods=['GET'])
def get_block_by_identifier(identifier):
    for block in blockchain.chain:
        # So sánh cả dạng int và string
        if block.hash == identifier:
            return Response(json.dumps(block.to_dict(), indent=2), mimetype='application/json')
        try:
            if block.index == int(identifier):
                return Response(json.dumps(block.to_dict(), indent=2), mimetype='application/json')
        except ValueError:
            continue
    return jsonify({"error": "Block not found"}), 404


@app.route('/balance/<address>', methods=['GET'])
def get_balance(address):
    balance = blockchain.state_db.get_balance(address)
    return Response(json.dumps({"address": address, "balance": balance}, indent=2), mimetype='application/json')


@app.route('/did/list', methods=['GET'])
def get_did_list():
    safe_registry = {}
    for did, data in blockchain.state_db.did_registry.items():
        safe_registry[did] = {
            "alias": data.get("alias"),
            "public_key_tuple": list(data.get("public_key_tuple", [])),
            "public_key_bytes": data.get("public_key_bytes").hex() if isinstance(data.get("public_key_bytes"), bytes) else data.get("public_key_bytes")
        }
    return Response(json.dumps(safe_registry, indent=2), mimetype='application/json')



@app.route('/did/<did>', methods=['GET'])
def get_did_info(did):
    data = blockchain.state_db.did_registry.get(did)
    if data:
        output = {
            "alias": data.get("alias"),
            "public_key_tuple": list(data.get("public_key_tuple", [])),
            "public_key_bytes": data.get("public_key_bytes").hex() if isinstance(data.get("public_key_bytes"), bytes) else data.get("public_key_bytes")
        }
        return Response(json.dumps(output, indent=2), mimetype='application/json')
    return Response(json.dumps({"error": "DID not found"}, indent=2), mimetype='application/json')


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
    return Response(json.dumps(mempool_data, indent=2), mimetype='application/json')


@app.route('/tx/<txid>', methods=['GET'])
def get_transaction_by_txid(txid):
    for block in blockchain.chain:
        for tx in block.transactions:
            if tx.txid == txid:
                return Response(json.dumps(tx.to_dict(), indent=2), mimetype='application/json')

    return Response(json.dumps({"error": "Transaction not found"}, indent=2), mimetype='application/json')


@app.route('/governance/proposals', methods=['GET'])
def get_governance_proposals():
    # Chuyển tất cả set thành list để JSON hóa
    safe_data = {
        k: {kk: list(vv) if isinstance(vv, set) else vv for kk, vv in v.items()}
        for k, v in blockchain.state_db.governance_proposals.items()
    }
    return Response(json.dumps(safe_data, indent=2), mimetype='application/json')


@app.route('/governance/proposal/<proposal_id>', methods=['GET'])
def get_governance_proposal(proposal_id):
    proposal = blockchain.state_db.governance_proposals.get(proposal_id)
    if proposal:
        # Convert the 'voters' set to a list before jsonify-ing
        # Create a copy to avoid modifying the original state directly if not intended
        serializable_proposal = proposal.copy()
        if "voters" in serializable_proposal and isinstance(serializable_proposal["voters"], set):
            serializable_proposal["voters"] = list(serializable_proposal["voters"])
        return Response(json.dumps(serializable_proposal, indent=2), mimetype='application/json')
    return Response(json.dumps({"error": f"proposal_id {proposal_id} not found"}, indent=2), mimetype='application/json')


@app.route('/governance/votes/<proposal_id>', methods=['GET'])
def get_governance_votes(proposal_id):
    proposal = blockchain.state_db.governance_proposals.get(proposal_id)
    if proposal:
        output = {
            "proposal_id": proposal_id,
            "votes_for": proposal.get("votes", {}).get("YES", 0),
            "votes_against": proposal.get("votes", {}).get("NO", 0),
            "finalized": proposal.get("finalized"),
            "result": proposal.get("result")
        }
        return Response(json.dumps(output, indent=2), mimetype='application/json')

    return Response(json.dumps({"error": f"proposal_id {proposal_id} not found"}, indent=2), mimetype='application/json')

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
            title = data.get("title", "")
            action = data.get("action")
            mint_target = data.get("mint_target")
            amount = data.get("amount")

            tx = Transaction(
                sender_public_key_bytes=wallet.public_key_raw_bytes,
                recipient_public_key_bytes=b"",
                amount=0,
                tx_type="PROPOSE",
                data=json.dumps({
                    "proposal_id": proposal_id,
                    "title": title,
                    "description": description,
                    "action": action,
                    "mint_target": mint_target,
                    "amount": amount
                })
            )

        elif tx_type == "TRANSFER":
            recipient = data["recipient"]
            amount = int(data["amount"])
            recipient_public_key_bytes = None

            if len(recipient) in (66, 130):
                recipient_public_key_bytes = bytes.fromhex(recipient)
            elif len(recipient) == 40:
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
                recipient_public_key_bytes=recipient_public_key_bytes,
                amount=amount,
                tx_type="TRANSFER",
                data=""
            )

        elif tx_type == "CROSS_TRANSFER":
            from_shard = data["from_shard"]
            to_shard = data["to_shard"]
            recipient = data["recipient"]
            amount = int(data["amount"])

            # Tạo giao dịch
            tx = Transaction(
                sender_public_key_bytes=wallet.public_key_raw_bytes,
                recipient_public_key_bytes=b'',
                amount=amount,
                tx_type="CROSS_TRANSFER",
                data=json.dumps({
                    "from_shard": from_shard,
                    "to_shard": to_shard,
                    "recipient": recipient,
                    "amount": amount
                }),
                timestamp=datetime.utcnow().isoformat() + "Z"
            )

        else:
            return jsonify({"error": f"Transaction type '{tx_type}' not supported"}), 400

        tx.signature = schnorr_sign(wallet.private_key_ecc, hash_message(tx.to_string_for_signing().encode()))

        success, reason = blockchain.add_transaction_to_mempool(tx)
        if success:
            await p2p_node.broadcast_message({
                "type": "TRANSACTION",
                "transaction": tx.to_dict()
            })
            return jsonify({"status": "success", "txid": tx.txid})
        else:
            return jsonify({"status": "failed", "reason": reason or "Giao dịch không hợp lệ"}), 400

    except Exception as e:
        print(f"An error occurred: {e}") # New log
        traceback.print_exc() # New log to print the full traceback
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/", methods=["GET"])
async def index():
    output = {
        "message": "VietID node is running!",
        "node_id": blockchain.node_id,
        "shard_id": blockchain.shard_id,
        "address": wallet.address
    }
    return Response(json.dumps(output, indent=2), mimetype='application/json')
    
@app.route("/health", methods=["GET"])
async def health():
    return Response(json.dumps({"status": "ok"}, indent=2), mimetype='application/json')

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

