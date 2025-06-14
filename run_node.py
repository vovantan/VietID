# ✅ run_node.py (bỏ xác thực TLS để đơn giản hóa cho môi trường demo Render)

import asyncio, os, json, socket, threading, time, argparse
from datetime import datetime, timedelta, timezone
from vietid17 import VietIDBlockchain, Wallet, Transaction, D_BFT_Consensus, hash_message, schnorr_sign
from p2p_node import P2PNode
from api_server import run_api


async def main():
    node_id = os.environ.get("NODE_ID")
    shard_id = int(os.environ.get("SHARD_ID", "0"))
    node_host = os.environ.get("NODE_HOST", "0.0.0.0")
    node_port = int(os.environ.get("P2P_PORT", "9000"))
    api_port = int(os.environ.get("PORT", "5001"))
    is_validator = os.environ.get("IS_VALIDATOR", "true").lower() == "true"
    all_validator_ids = os.environ.get("ALL_VALIDATOR_IDS", "").split(",")

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
        ssl_context_server=None,
        ssl_context_client=None
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
