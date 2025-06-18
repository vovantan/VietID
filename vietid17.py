import hashlib, os, json, time, asyncio, zlib
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError

# =============================================================================
# Helper Functions (moved directly here for self-containment)
# =============================================================================

def hash_message(message_bytes: bytes) -> bytes:
    return hashlib.sha256(message_bytes).digest()

def schnorr_sign(private_key_ecc: SigningKey, message_hash: bytes) -> bytes:
    signature = private_key_ecc.sign(message_hash)
    return signature

def schnorr_verify(public_key_ecc: VerifyingKey, signature: bytes, message_hash: bytes) -> bool:
    try:
        return public_key_ecc.verify(signature, message_hash)
    except BadSignatureError:
        return False

def get_shard_for_transaction(tx, num_shards): # CROSS_TRANSFER
    """Định tuyến giao dịch vào shard."""
    if tx.tx_type == "CROSS_TRANSFER":
        try:
            tx_data = json.loads(tx.data)
            if "from_shard" in tx_data and isinstance(tx_data["from_shard"], int):
                return tx_data["from_shard"]
            else:
                print(f"[ERROR] CROSS_TRANSFER data missing or invalid 'from_shard'. Txid: {tx.txid[:10]}...")
                return 0 
        except (json.JSONDecodeError, KeyError):
            print(f"[ERROR] Lỗi phân tích data của CROSS_TRANSFER để lấy from_shard. Txid: {tx.txid[:10]}...")
            return 0 

    elif tx.tx_type == "RECEIVE_TRANSFER":
        try:
            tx_data = json.loads(tx.data)
            to_shard_raw = tx_data.get("to_shard")
            return int(to_shard_raw)
        except Exception as e:
            print(f"[ERROR] ❌ Không thể đọc to_shard trong RECEIVE_TRANSFER: {e}")
            return 0

    if tx.sender_public_key_bytes:
        sender_hash = hashlib.sha256(tx.sender_public_key_bytes).hexdigest()
        return int(sender_hash, 16) % num_shards
    else:
        return 0

# =============================================================================
# Transaction
# =============================================================================
class Transaction:
    def __init__(self, sender_public_key_bytes: bytes, recipient_public_key_bytes: bytes,
                 amount: float, tx_type: str, data: str = "", timestamp: str = None, signature: str = None):
        self.sender_public_key_bytes = sender_public_key_bytes
        self.recipient_public_key_bytes = recipient_public_key_bytes
        self.amount = amount
        self.tx_type = tx_type
        self.data = data
        self.timestamp = timestamp if timestamp else datetime.now(timezone.utc).isoformat()
        self.signature = signature
        self.txid = self.calculate_txid()
        

    def calculate_txid(self) -> str:
        tx_string = f"{self.sender_public_key_bytes.hex()}{self.recipient_public_key_bytes.hex()}{self.amount}{self.tx_type}{self.data}{self.timestamp}"
        return hashlib.sha256(tx_string.encode('utf-8')).hexdigest()

    def to_dict(self) -> dict:
        """Chuyển đổi đối tượng Transaction thành một dictionary để dễ dàng tuần tự hóa."""
        return {
            "sender_public_key": self.sender_public_key_bytes.hex(),
            "recipient_public_key": self.recipient_public_key_bytes.hex(),
            "amount": self.amount,
            "tx_type": self.tx_type,
            "data": self.data,
            "timestamp": self.timestamp,
            "txid": self.txid,
            "signature": self.signature.hex() if self.signature else ""
        }

    @classmethod
    def from_dict(cls, tx_dict: dict):
        try:
            sender_pk_bytes = bytes.fromhex(tx_dict["sender_public_key"])
            recipient_pk_bytes = bytes.fromhex(tx_dict["recipient_public_key"])
            signature_bytes = bytes.fromhex(tx_dict["signature"]) if tx_dict.get("signature") else None
        except Exception as e:
            print(f"[Transaction] ❌ Lỗi chuyển đổi public key từ hex: {e}")
            raise

        tx = cls(
            sender_public_key_bytes=sender_pk_bytes,
            recipient_public_key_bytes=recipient_pk_bytes,
            amount=tx_dict["amount"],
            tx_type=tx_dict["tx_type"],
            data=tx_dict.get("data", ""),
            timestamp=tx_dict["timestamp"],
            signature=signature_bytes
        )

        if tx.calculate_txid() != tx_dict["txid"]:
            print(f"[Transaction] ⚠️ TXID không khớp: dict={tx_dict['txid']}, calc={tx.calculate_txid()}")
        tx.txid = tx_dict["txid"]
        return tx


    def to_string_for_signing(self) -> str:
        return (
            self.sender_public_key_bytes.hex() +
            self.recipient_public_key_bytes.hex() +
            str(self.amount) +
            self.tx_type +
            self.data +
            str(self.timestamp)
        )

    
    def verify_signature(self) -> bool:
        if self.tx_type == "RECEIVE_TRANSFER":
            return True
        try:
            public_key_ecc = VerifyingKey.from_string(
                self.sender_public_key_bytes,
                curve=SECP256k1
            )

            message = self.to_string_for_signing()
            message_hash = hash_message(message.encode('utf-8'))

            # Kiểm tra chữ ký
            return schnorr_verify(public_key_ecc, self.signature, message_hash)

        except Exception as e:
            print(f"[verify_signature] ❌ Lỗi: {e}")
            return False
    
    def is_valid(self) -> bool:

        if not self.sender_public_key_bytes or not self.signature:
            return False

        if self.tx_type == "RECEIVE_TRANSFER":
            return True  # Không cần chữ ký
        try:
            public_key_ecc = VerifyingKey.from_string(self.sender_public_key_bytes, curve=SECP256k1)
            message_hash = hash_message(self.to_string_for_signing().encode('utf-8'))

            if not schnorr_verify(public_key_ecc, self.signature, message_hash):
                return False
        except Exception as e:
            return False
        
        if self.tx_type == "DID_REGISTER":
            try:
                tx_data = json.loads(self.data)
                
                if not tx_data.get("did") or not tx_data.get("public_key_tuple"):
                    return False
            except json.JSONDecodeError:
                return False

        if self.tx_type == "TRANSFER" and self.amount <= 0:
            return False
        
        if self.tx_type == "GOVERNANCE_PROPOSAL":
            try:
                proposal = json.loads(self.data)
                return "proposal_id" in proposal and "description" in proposal
            except:
                return False

        if self.tx_type == "VOTE":
            try:
                vote = json.loads(self.data)
                return "proposal_id" in vote and "vote" in vote and vote["vote"] in ["YES", "NO"]
            except:
                return False

        return True
    
    @property
    def sender_address(self):
        if not self.sender_public_key_bytes:
            return None
        return Wallet.public_key_bytes_to_address(self.sender_public_key_bytes)

    @property
    def recipient_address(self):
        if not self.recipient_public_key_bytes:
            return None
        return Wallet.public_key_bytes_to_address(self.recipient_public_key_bytes)


# =============================================================================
# Wallet
# =============================================================================

class Wallet:
    def __init__(self, private_key_pem: bytes = None):
        self.private_key_pem = private_key_pem
        self.public_key_pem = None
        self.address = None
        self.alias = None
        self.public_key_tuple = None
        self.private_key_ecc = None 
        self.public_key_ecc = None

        if self.private_key_pem:
            self._load_keys()
        else:
            self._generate_keys()

    def _generate_keys(self):
        sk = SigningKey.generate(curve=SECP256k1)
        self.private_key_pem = sk.to_pem()
        self.public_key_pem = sk.get_verifying_key().to_pem()
        self.private_key_ecc = sk
        self.public_key_ecc = sk.get_verifying_key()
        vk = sk.get_verifying_key()
        self.public_key_tuple = (vk.pubkey.point.x(), vk.pubkey.point.y())
        self.address = Wallet.public_key_bytes_to_address(self.public_key_raw_bytes)
        print(f"Ví mới được tạo. Địa chỉ: {self.address[:10]}...")

    def _load_keys(self):
        try:
            sk = SigningKey.from_pem(self.private_key_pem)
            self.private_key_pem = sk.to_pem()
            self.public_key_pem = sk.get_verifying_key().to_pem()
            self.private_key_ecc = sk 
            self.public_key_ecc = sk.get_verifying_key()

            vk = sk.get_verifying_key()
            self.public_key_tuple = (vk.pubkey.point.x(), vk.pubkey.point.y())
            self.address = Wallet.public_key_bytes_to_address(self.public_key_raw_bytes)
            print(f"Ví đã được tải. Địa chỉ: {self.address[:10]}...")

        except Exception as e:
            print(f"Lỗi tải khóa riêng tư: {e}")
            print("Tạo ví mới thay thế...")
            self._generate_keys()
    
    @property
    def public_key_raw_bytes(self) -> bytes:
        return self.public_key_ecc.to_string()
    
    def get_public_key_hex(self):
        return self.public_key_raw_bytes.hex()

    @staticmethod
    def public_key_bytes_to_address(public_key_bytes: bytes) -> str:
        import hashlib
        sha = hashlib.sha256(public_key_bytes).digest()
        ripemd = hashlib.new('ripemd160', sha).hexdigest()
        return ripemd

# =============================================================================
# Block
# =============================================================================
class Block:
    def __init__(self, index: int, timestamp: float, transactions: list, previous_hash: str, nonce: int = 0,
                 hash: str = None, shard_id: int = 0, validator_id: str = "", view_number: int = 0, sequence_number: int = 0, signature: bytes = None):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.view_number = view_number 
        self.sequence_number = sequence_number
        self.nonce = nonce
        self.shard_id = shard_id
        self.validator_id = validator_id 
        self.hash = hash if hash else self.calculate_hash()
        self.signature = signature 

    def calculate_hash(self) -> str:
        transactions_data_for_hash = ""
        sorted_transactions = sorted(self.transactions, key=lambda tx: tx.txid)
        for tx in sorted_transactions:
            transactions_data_for_hash += tx.to_string_for_signing()
        block_string = (
            f"{self.index}"
            f"{self.previous_hash}"
            f"{self.timestamp}"
            f"{transactions_data_for_hash}"
            f"{self.validator_id}"
            f"{self.view_number}"
            f"{self.sequence_number}"
            f"{self.nonce}"
            f"{self.shard_id}"
        )

        return hash_message(block_string.encode('utf-8')).hex()

    def to_dict(self, include_signature: bool = True) -> dict:
        transactions_dicts = [tx.to_dict() for tx in self.transactions]
        
        block_dict = {
            "index": self.index,
            "transactions": transactions_dicts,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "validator_id": self.validator_id,
            "view_number": self.view_number,
            "sequence_number": self.sequence_number,
            "nonce": self.nonce,
            "shard_id": self.shard_id,
            "hash": self.hash
        }

        if include_signature and self.signature:
            block_dict["signature"] = self.signature.hex()
        else:
            block_dict["signature"] = ""
        return block_dict
    
    @classmethod
    def from_dict(cls, data: dict):
        transactions = [Transaction.from_dict(tx_data) for tx_data in data["transactions"]]
        return cls(
            index=data["index"],
            timestamp=data["timestamp"],
            transactions=transactions,
            previous_hash=data["previous_hash"],
            nonce=data["nonce"],
            hash=data["hash"],
            shard_id=data.get("shard_id", 0),
            validator_id=data.get("validator_id", "")
        )

# =============================================================================
# State Management
# =============================================================================
class StateDB:
    def __init__(self, shard_id: int):
        self.shard_id = shard_id
        self.balance = defaultdict(int)  # address -> balance (đã sửa lại thành int để tránh lỗi số học dấu phẩy động)
        self.did_registry = {}  # Stores DID -> public_key_tuple
        self.alias_to_did = {}  # Stores alias -> DID
        self.state_snapshots = {} # block_index -> (block_hash, snapshot_data_compressed)
        self.cross_shard_messages = []
        self.total_supply = 0
        self.proposals = {}
        self.governance_proposals = {}
        
    def register_did(self, did: str, public_key_tuple: tuple, alias: str = None) -> bool:
        if did in self.did_registry:
            print(f"[StateDB] DID {did} đã tồn tại.")
            return False
        if alias and alias in self.alias_to_did:
            print(f"[StateDB] Alias {alias} đã được sử dụng.")
            return False
        
        self.did_registry[did] = public_key_tuple
        if alias:
            self.alias_to_did[alias] = did
        print(f"[StateDB] Đã đăng ký DID: {did} (Alias: {alias if alias else 'None'})")
        return True

    def get_public_key_for_did(self, did: str) -> tuple:
        return self.did_registry.get(did)

    def get_did_for_alias(self, alias: str) -> str:
        return self.alias_to_did.get(alias)
    
    def get_alias_for_did(self, did: str) -> str:
        # Tra cứu ngược đơn giản để gỡ lỗi/kiểm tra
        for alias_key, registered_did in self.alias_to_did.items():
            if registered_did == did:
                return alias_key
        return None

    def get_balance(self, address: str) -> int:
        return self.balance[address]

    def update_balance(self, address: str, amount: int):
        self.balance[address] += amount
        print(f"[StateDB] Cập nhật số dư cho {address}: {self.balance[address]}")

    def simulate_transaction(self, tx: Transaction) -> bool:
        if tx.tx_type == "TRANSFER":
            return tx.sender_address in self.balance and self.balance[tx.sender_address] >= tx.amount
        return True

    # Đổi tên từ apply_block thành apply_transactions để khớp với VietIDBlockchain.add_block
    def apply_transactions(self, transactions: list) -> bool:
        """Áp dụng một danh sách các giao dịch vào trạng thái hiện tại của StateDB."""
        for tx in transactions:
            print(f"[StateDB] Áp dụng giao dịch: {tx.txid[:10]}... (Loại: {tx.tx_type})")
            if tx.tx_type == "TRANSFER":
                # Giả định đối tượng Transaction có sender_address, recipient_address, amount
                # Cần kiểm tra người gửi có đủ số dư
                if tx.sender_address in self.balance and self.balance[tx.sender_address] >= tx.amount:
                    self.update_balance(tx.sender_address, -tx.amount)
                    self.update_balance(tx.recipient_address, tx.amount)
                else:
                    print(f"[StateDB] Giao dịch TRANSFER {tx.txid[:10]}... không đủ số dư của người gửi hoặc người gửi không tồn tại.")
                    return False # Giao dịch không hợp lệ, không thể áp dụng block này
            elif tx.tx_type == "DID_REGISTER":
                try:
                    tx_data = json.loads(tx.data)
                    did = tx_data.get("did")
                    public_key_list = tx_data.get("public_key_tuple")
                    alias = tx_data.get("alias")

                    if not did or not public_key_list:
                        print(f"[StateDB] Giao dịch DID_REGISTER {tx.txid[:10]}... thiếu thông tin cần thiết.")
                        return False

                    public_key_tuple = tuple(public_key_list)
                    public_key_bytes = tx.sender_public_key_bytes

                    self.did_registry[did] = {
                        "alias": alias,
                        "public_key_tuple": public_key_tuple,
                        "public_key_bytes": tx.sender_public_key_bytes  # ✅ cần thiết để tra lại từ address
                    }

                    print(f"[StateDB] Đã đăng ký DID: {did} (Alias: {alias})")
                except json.JSONDecodeError:
                    print(f"[StateDB] Giao dịch DID_REGISTER {tx.txid[:10]}... dữ liệu không phải JSON hợp lệ.")
                    return False
                except Exception as e:
                    print(f"[StateDB] Lỗi khi xử lý giao dịch DID_REGISTER {tx.txid[:10]}...: {e}")
                    return False
                '''
                # Đoạn này đòi hỏi phải có số dư
                elif tx.tx_type == "CROSS_TRANSFER":
                    try:
                        tx_data = json.loads(tx.data)
                        to_shard = tx_data["to_shard"]
                        recipient = tx_data["recipient_address"]
                        amount = tx_data["amount"]

                        sender_address = hashlib.sha256(tx.sender_public_key_bytes).hexdigest()
                        
                        if self.balance[sender_address]: >= amount: # tạm thời không đặt điều kiện với số dư
                            self.update_balance(sender_address, -amount)
                            print(f"[StateDB] ✅ CROSS_TRANSFER: -{amount} từ {sender_address[:10]}...")

                            # ✅ Trả về RECEIVE_TRANSFER để xử lý sau
                            receive_tx = Transaction(
                                sender_public_key_bytes=b'',
                                recipient_public_key_bytes=b'',
                                amount=amount,
                                tx_type="RECEIVE_TRANSFER",
                                data=json.dumps({
                                    "recipient_address": recipient,
                                    "amount": amount
                                }),
                                timestamp=datetime.utcnow().isoformat() + "Z"
                            )

                            # 👉 Lưu vào self.cross_shard_messages để xử lý sau
                            if hasattr(self, "cross_shard_messages"):
                                self.cross_shard_messages.append((to_shard, receive_tx))
                            return True
                        else:
                            print(f"[StateDB] ❌ Không đủ số dư.")
                            return False
                '''
            # Đoạn này dùng để test với số dư chấp nhận là số âm
            elif tx.tx_type == "CROSS_TRANSFER":
                try:
                    tx_data = json.loads(tx.data)
                    from_shard = tx_data["from_shard"]
                    recipient = tx_data["recipient_address"]
                    amount = tx_data["amount"]
                    to_shard = tx_data["to_shard"] #int(hashlib.sha256(recipient.encode()).hexdigest(), 16) % 3

                    if self.shard_id == from_shard:
                        sender_address = hashlib.sha256(tx.sender_public_key_bytes).hexdigest()
                        self.update_balance(sender_address, -amount)
                        print(f"[StateDB] ✅ CROSS_TRANSFER: -{amount} từ {sender_address[:10]}...")
                        print(f"[DEBUG] CROSS_TRANSFER đang xử lý: from {from_shard} → {to_shard}")
                        print(f"[DEBUG] Tạo RECEIVE_TRANSFER gửi đến shard {to_shard}")

                        receive_tx = Transaction(
                            sender_public_key_bytes=b'',
                            recipient_public_key_bytes=b'',
                            amount=amount,
                            tx_type="RECEIVE_TRANSFER",
                            data=json.dumps({
                                "recipient_address": recipient,
                                "amount": amount,
                                "to_shard": to_shard
                            }),
                            timestamp=datetime.utcnow().isoformat() + "Z"
                        )
                        print(f"[DEBUG] RECEIVE_TRANSFER tx: {receive_tx.to_dict()}")


                        if hasattr(self, "cross_shard_messages"):
                            self.cross_shard_messages.append((to_shard, receive_tx))
                            print(f"[StateDB] 📤 Chuẩn bị gửi RECEIVE_TRANSFER sang shard {to_shard}")
                    else:
                        print(f"[StateDB] ⏩ Bỏ qua CROSS_TRANSFER vì không phải shard nguồn")
                    return True
                except Exception as e:
                    print(f"[StateDB] ❌ Lỗi CROSS_TRANSFER: {e}")
                    return False
            elif tx.tx_type == "RECEIVE_TRANSFER":
                try:
                    tx_data = json.loads(tx.data)
                    recipient = tx_data["recipient_address"]
                    amount = tx_data["amount"]
                    self.update_balance(recipient, amount)
                    print(f"[StateDB] ✅ RECEIVE_TRANSFER: +{amount} vào {recipient[:10]}...")
                except Exception as e:
                    print(f"[StateDB] ❌ Lỗi xử lý RECEIVE_TRANSFER: {e}")
                    return False
                '''
                elif tx.tx_type == "GOVERNANCE_PROPOSAL":
                    proposal = json.loads(tx.data)
                    pid = proposal["proposal_id"]
                    desc = proposal["description"]
                    if pid not in self.governance_proposals:
                        self.governance_proposals[pid] = {"description": desc, "votes": {"YES": 0, "NO": 0}}
                        print(f"[Governance] 🗳️ Đề xuất mới: {pid} - {desc}")
                    else:
                        print(f"[Governance] ⚠️ Đề xuất {pid} đã tồn tại.")
                        return False
                elif tx.tx_type == "VOTE":
                    vote = json.loads(tx.data)
                    pid = vote["proposal_id"]
                    choice = vote["vote"]

                    if pid in self.governance_proposals:
                        sender_key = tx.sender_address

                        proposal = self.governance_proposals[pid]

                        if sender_key in proposal.get("voters", set()):
                            print(f"[Governance] ⚠️ {sender_key[:10]}... đã vote cho {pid} trước đó.")
                            return False
                        
                        # Trọng số = số dư token
                        weight = self.get_balance(sender_key)
                        
                        if weight == 0:
                            print(f"[Governance] ❌ {sender_key[:10]}... không có token để vote.")
                            return False
                        # sử dụng đoạn này phải thực hiện MINT trước
                        
                        #if weight == 0:
                            #print(f"[Governance] ⚠️ {sender_key[:10]}... không có token, vote trọng số = 1.")
                            #weight = 1  # cho phép vote, coi như 1 token
                        
                        proposal["votes"][choice] += weight
                        proposal.setdefault("voters", set()).add(sender_key)
                        print(f"[Governance] ✅ {sender_key[:10]}... vote {choice} (trọng số {weight}) cho {pid}. Tổng YES: {proposal['votes']['YES']}, NO: {proposal['votes']['NO']}")

                        # Xét duyệt nếu đủ điều kiện
                        total_votes = proposal["votes"]["YES"] + proposal["votes"]["NO"]
                        yes_ratio = proposal["votes"]["YES"] / total_votes if total_votes else 0

                        if yes_ratio >= 0.66:  # 2/3 đồng thuận
                            proposal["finalized"] = True
                            proposal["result"] = "PASSED"
                            print(f"[Governance] ✅ Đề xuất {pid} đã được thông qua.")
                        elif proposal["votes"]["NO"] > proposal["votes"]["YES"]:
                            proposal["finalized"] = True
                            proposal["result"] = "REJECTED"
                            print(f"[Governance] ❌ Đề xuất {pid} đã bị từ chối.")
                    else:
                        print(f"[Governance] ❌ Không tìm thấy đề xuất {pid}")
                        return False
                '''
            elif tx.tx_type == "GOVERNANCE_PROPOSAL":
                try:
                    print(f"[DEBUG] tx.data = {tx.data}")
                    proposal_data = json.loads(tx.data)
                    proposal_id = proposal_data["proposal_id"]
                    description = proposal_data.get("description", "")

                    if proposal_id not in self.governance_proposals or not self.governance_proposals[proposal_id]["finalized"]:
                        self.governance_proposals[proposal_id] = {
                            "description": description,
                            "votes": {"YES": 0, "NO": 0},
                            "voters": set(),
                            "finalized": False,
                            "result": None,
                            "action": proposal_data.get("action"),
                            "mint_target": proposal_data.get("mint_target"),
                            "amount": proposal_data.get("amount"),
                        }
                    print(f"[GOV] 🗳️ Đã tạo đề xuất '{proposal_id}'")
                except Exception as e:
                    print(f"[GOV] ❌ Lỗi khi xử lý GOVERNANCE_PROPOSAL: {e}")
                    return False

            elif tx.tx_type == "VOTE":
                try:
                    vote_data = json.loads(tx.data)
                    proposal_id = vote_data["proposal_id"]
                    vote = vote_data["vote"]  # "YES" hoặc "NO"
                    pubkey_hex = tx.sender_public_key_bytes.hex()

                    proposal = self.governance_proposals.get(proposal_id)
                    if not proposal:
                        print(f"[GOV] ❌ Đề xuất '{proposal_id}' không tồn tại.")
                        return False
                    if proposal["finalized"]:
                        print(f"[GOV] ⛔ Đề xuất '{proposal_id}' đã kết thúc.")
                        return False
                    if pubkey_hex in proposal["voters"]:
                        print(f"[GOV] ⛔ Người dùng đã vote cho '{proposal_id}'")
                        return False

                    if vote not in ("YES", "NO"):
                        print(f"[GOV] ❌ Phiếu không hợp lệ.")
                        return False

                    proposal["votes"][vote] += 1
                    proposal["voters"].add(pubkey_hex)  # ✅ Đúng với kiểu `set`
                    print(f"[GOV] 🗳️ Vote '{vote}' cho '{proposal_id}' từ {pubkey_hex[:10]}...")

                    self.try_finalize_proposal(proposal_id)
                except Exception as e:
                    print(f"[GOV] ❌ Lỗi xử lý phiếu vote: {e}")
                    return False
                '''
                elif tx.tx_type == "MINT":
                    data = json.loads(tx.data)
                    recipient = data["recipient_address"]
                    amount = data["amount"]
                    if amount > 0:
                        self.balance[recipient] += amount
                        self.total_supply += amount
                        print(f"[Tokenomics] ✅ MINT {amount} token đến {recipient[:10]}..., tổng cung: {self.total_supply}")
                        return True
                    else:
                        print("[Tokenomics] ❌ Số lượng MINT không hợp lệ.")
                        return False
                '''
            elif tx.tx_type == "MINT":
                if not tx.data:
                    print(f"[⚠️ MINT] Dữ liệu rỗng, bỏ qua giao dịch {tx.txid[:10]}...")
                    return False
                try:
                    data = json.loads(tx.data)
                    recipient = data.get("recipient") or data.get("recipient_address")
                    amount = data["amount"]
                    if recipient and amount > 0:
                        self.balance[recipient] += amount
                        self.total_supply += amount
                        print(f"[Tokenomics] ✅ MINT {amount} token đến {recipient[:10]}..., tổng cung: {self.total_supply}")
                        return True
                    else:
                        print(f"[❌ MINT] Thiếu trường hoặc số lượng không hợp lệ.")
                        return False
                except Exception as e:
                    print(f"[❌ MINT] Lỗi khi xử lý dữ liệu JSON: {e}")
                    return False
            
            elif tx.tx_type == "PROPOSE":
                proposal = json.loads(tx.data)
                proposal_id = proposal["proposal_id"]
                title = proposal.get("title", "")
                description = proposal["description"]
                self.proposals[proposal_id] = {
                    "title": title,
                    "description": description,
                    "creator": tx.sender_public_key_bytes.hex(),
                    "votes": {"YES": 0, "NO": 0},
                    "voters": [],
                    "finalized": False,
                    "result": None
                }
                print(f"[Governance] ✅ Đã thêm đề xuất: {proposal_id}")
                return True
            
        return True # Tất cả giao dịch đã được áp dụng thành công
        
    def try_finalize_proposal(self, proposal_id):
        proposal = self.governance_proposals.get(proposal_id)
        if not proposal or proposal["finalized"]:
            return False

        quorum = 2
        yes = proposal["votes"]["YES"]
        no = proposal["votes"]["NO"]

        print(f"[DEBUG] ✅ Đang kiểm tra đề xuất '{proposal_id}' | YES: {yes}, NO: {no}, quorum: {quorum}")

        if yes + no >= quorum:
            if yes > no:
                proposal["result"] = "PASSED"
                print(f"[GOV] ✅ Đề xuất '{proposal_id}' đã PASSED")

                if proposal.get("action") == "MINT":
                    target = proposal.get("mint_target")
                    try:
                        amount = int(proposal.get("amount", 0))
                    except Exception as e:
                        print(f"[GOV] ❌ amount không hợp lệ: {e}")
                        amount = 0

                    print(f"[DEBUG] Chuẩn bị MINT {amount} token cho {target}")
                    if target and amount > 0:
                        self.update_balance(target, amount)
                        self.total_supply += amount
                        proposal["executed"] = True
                        print(f"[TOKEN] 💸 MINT {amount} token cho {target}")
                    else:
                        print(f"[GOV] ❌ Thiếu thông tin MINT hoặc amount = 0")
            else:
                proposal["result"] = "REJECTED"
                print(f"[GOV] ❌ Đề xuất '{proposal_id}' bị REJECTED")

            proposal["finalized"] = True
            return True

        return False
        
    def create_snapshot(self, block_index: int, block_hash: str):
        # Tạo một snapshot của trạng thái hiện tại
        current_state = {
            'did_registry': dict(self.did_registry),
            'alias_to_did': dict(self.alias_to_did),
            'balance': dict(self.balance)
        }
        compressed_state = zlib.compress(json.dumps(current_state).encode('utf-8'))
        self.state_snapshots[block_index] = (block_hash, compressed_state)
        print(f"[StateDB] Snapshot trạng thái tạo tại block {block_index}.")

    def load_snapshot(self, block_index: int) -> bool:
        if block_index not in self.state_snapshots:
            print(f"[StateDB] Không tìm thấy snapshot cho block {block_index}.")
            return False
        
        block_hash, compressed_state = self.state_snapshots[block_index]
        decompressed_state = json.loads(zlib.decompress(compressed_state).decode('utf-8'))
        
        self.did_registry = decompressed_state['did_registry']
        self.alias_to_did = dict(decompressed_state['alias_to_did']) # Giữ nguyên là dict
        self.balance = defaultdict(int, decompressed_state['balance'])
        
        print(f"[StateDB] Đã tải snapshot trạng thái từ block {block_index} ({block_hash[:10]}...).")
        return True

    def mint_tokens(self, address: str, amount: int) -> bool:
        if amount <= 0:
            return False
        self.balance[address] += amount
        self.total_supply += amount
        print(f"[Tokenomics] ✅ Mint {amount} tokens đến {address[:10]}..., Tổng cung: {self.total_supply}")
        return True

    def burn_tokens(self, address: str, amount: int) -> bool:
        if self.balance[address] < amount:
            print(f"[Tokenomics] ❌ Không đủ số dư để burn.")
            return False
        self.balance[address] -= amount
        self.total_supply -= amount
        print(f"[Tokenomics] 🔥 Burn {amount} tokens từ {address[:10]}..., Tổng cung: {self.total_supply}")
        return True

    def get_total_supply(self) -> int:
        return self.total_supply

    def get_pubkey_by_address(self, address: str) -> bytes | None:
        print("[DEBUG] Toàn bộ DID registry:")
        for did, data in self.did_registry.items():
            pubkey = data.get("public_key_bytes")
            if pubkey:
                derived_address = self.hash_public_key_bytes(pubkey)
                print(f"[DEBUG] So sánh {address} <=> {derived_address} từ DID {did}")
                if derived_address == address:
                    print("[DEBUG] ✅ Khớp địa chỉ!")
                    return pubkey
        print(f"[DEBUG] ❌ Không tìm thấy địa chỉ {address} trong did_registry")
        return None


    def hash_public_key_bytes(self, pubkey: bytes) -> str:
        sha = hashlib.sha256(pubkey).digest()
        ripemd = hashlib.new('ripemd160', sha).hexdigest()
        return ripemd
# =============================================================================
# Blockchain
# =============================================================================
class VietIDBlockchain:
    def __init__(self, node_id: str, shard_id: int): # Added node_id and shard_id
        self.chain = []
        self.pending_transactions = []
        self.difficulty = 2
        self.dbft_consensus = None
        self.transaction_pool = asyncio.Queue()
        self.node_id = node_id # Store node_id
        self.shard_id = shard_id # Store shard_id
        self.state_db = StateDB(self.shard_id)
        self.registered_nodes = {}
        self.block_proposals = defaultdict(dict)
        self.votes = defaultdict(lambda: defaultdict(set))
        self.create_genesis_block()
        self.mempool = {}
        self.transaction_class = Transaction

    def create_genesis_block(self):
        # Create the very first block in the blockchain
        genesis_transactions = [] # Genesis block typically has no transactions or special initial ones
        genesis_block = Block(
            index=0,
            timestamp=1700000000,
            transactions=genesis_transactions,
            previous_hash="0", # Special hash for the genesis block's previous hash
            nonce=0,
            view_number=0,      # TRUYỀN RÕ RÀNG view_number
            sequence_number=0   # TRUYỀN RÕ RÀNG sequence_number
        )
        self.add_block(genesis_block)
        print(f"[Blockchain] Khối khởi tạo đã được tạo: {genesis_block.hash[:10]}...")

    def add_block(self, block: Block) -> bool:
        """Thêm một block mới vào chuỗi nếu nó hợp lệ."""
        
        # Nếu đây là genesis block (index 0), chúng ta thêm nó trực tiếp mà không cần validation.
        # Chúng ta giả định genesis block luôn hợp lệ.
        if block.index == 0:
            # Không làm gì thêm ở đây, bỏ qua bước validate với block trước đó
            pass
        else:
            # Đối với các block không phải genesis, phải có block trước đó để validate.
            if not self.chain:
                print("[Blockchain] Lỗi: Chuỗi trống khi cố gắng thêm block không phải genesis.")
                return False # Không thể thêm block nếu không có block nào trước đó
            
            # Lấy block cuối cùng để so sánh
            latest_block = self.get_latest_block() 
            
            # Kiểm tra tính hợp lệ của block mới với block cuối cùng
            if not self.is_valid_new_block(block, latest_block):
                print("[Blockchain] Block không hợp lệ và không được thêm vào chuỗi.")
                return False

        # Áp dụng các giao dịch vào trạng thái trước khi thêm block vào chuỗi
        if not self.state_db.apply_transactions(block.transactions):
            print("[Blockchain] Lỗi khi áp dụng giao dịch vào trạng thái. Block không được thêm.")
            return False

        # Thêm block vào chuỗi
        self.chain.append(block)

        # Xóa các giao dịch đã được đưa vào block khỏi mempool
        for tx in block.transactions:
            if tx.txid in self.mempool:
                del self.mempool[tx.txid]
        print(f"[Blockchain] Đã thêm block {block.index} ({block.hash[:10]}...) thành công. Tổng số block: {len(self.chain)}")

        # Tạo snapshot trạng thái định kỳ (ví dụ: mỗi 10 block)
        if block.index % 10 == 0:
            self.state_db.create_snapshot(block.index, block.hash)
            self.last_state_snapshot_block_index = block.index
            print(f"[Blockchain] Đã tạo snapshot trạng thái tại block {block.index}.")

        # Gửi các cross-shard message (nếu có)
        # Sau khi block được áp dụng
        if hasattr(self.state_db, "cross_shard_messages"):
            for to_shard, receive_tx in self.state_db.cross_shard_messages:
                print(f"[Blockchain] 📤 Gửi RECEIVE_TRANSFER tx đến shard {to_shard}")
                asyncio.create_task(self.p2p_node.send_to_shard({
                    "type": "TRANSACTION",
                    "transaction": receive_tx.to_dict()
                }, target_shard=to_shard))

            self.state_db.cross_shard_messages.clear()
        return True

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def get_block_by_index(self, index: int): #mới thêm
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None
    
    def add_transaction(self, transaction: Transaction) -> bool:

        if transaction.txid in self.mempool or self.is_transaction_in_chain(transaction.txid):
            print(f"[Blockchain] Giao dịch {transaction.txid[:10]}... đã tồn tại hoặc đã được xử lý.")
            return False

        shard_for_tx = get_shard_for_transaction(transaction, num_shards=3)  # Giả sử 3 shard
        if shard_for_tx != self.shard_id:
            print(f"[Blockchain] ⚠️ Giao dịch {transaction.txid[:10]}... không thuộc shard {self.shard_id}, bỏ qua.")
            return False
        
        # Basic validation (e.g., signature verification)
        if not transaction.verify_signature():
            print(f"[Blockchain] Lỗi: Giao dịch {transaction.txid[:10]}... có chữ ký không hợp lệ.")
            return False
        
        self.mempool[transaction.txid] = transaction
        print(f"[Blockchain] Đã thêm giao dịch {transaction.txid[:10]}... vào mempool. Tổng số: {len(self.mempool)}")
        return True

    def is_transaction_in_chain(self, txid: str) -> bool:
        for block in self.chain:
            for tx in block.transactions:
                if tx.txid == txid:
                    return True
        return False

    def is_valid_new_block(self, block: Block, last_block: Block) -> bool:
        if last_block.index + 1 != block.index:
            print(f"Index block không hợp lệ: {block.index} thay vì {last_block.index + 1}")
            return False
        if last_block.hash != block.previous_hash:
            print(f"Hash trước đó không khớp: {block.previous_hash} thay vì {last_block.hash}")
            return False
        if block.calculate_hash() != block.hash: # Recalculate hash to verify
            print(f"Hash block không khớp: {block.hash} thay vì {block.calculate_hash()}")
            return False
        # Additional checks: timestamp, transactions validity (already done when adding to mempool)
        #if datetime.fromisoformat(block.timestamp.replace('Z', '+00:00')) <= datetime.fromisoformat(last_block.timestamp.replace('Z', '+00:00')):
        try:
            ts_block = float(block.timestamp) if isinstance(block.timestamp, (float, int)) else datetime.fromisoformat(block.timestamp.replace('Z', '+00:00')).timestamp()
            ts_last = float(last_block.timestamp) if isinstance(last_block.timestamp, (float, int)) else datetime.fromisoformat(last_block.timestamp.replace('Z', '+00:00')).timestamp()
            if ts_block <= ts_last:
                print(f"Timestamp block không hợp lệ: {block.timestamp} phải sau {last_block.timestamp}")
                return False
        except Exception as e:
            print(f"[Blockchain] ❌ Lỗi xử lý timestamp: {e}")
            return False

        # Verify signatures of transactions within the block
        for tx in block.transactions:
            if not tx.verify_signature():
                print(f"Giao dịch {tx.txid[:10]}... trong block có chữ ký không hợp lệ.")
                return False
        return True
    
    def is_chain_valid(self, chain: list) -> bool:
        if not chain:
            return False
        if len(chain) == 0:
            return True # Empty chain could be considered valid in some contexts (e.g., just started)
        if chain[0].index != 0 or chain[0].previous_hash != "0": # Basic genesis check
            return False
        
        # Temporarily apply state for validation
        temp_state_db = StateDB()
        
        # Re-verify genesis block hash
        if chain[0].calculate_hash() != chain[0].hash:
            print(f"Genesis block hash không khớp: {chain[0].hash} thay vì {chain[0].calculate_hash()}")
            return False

        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i-1]

            if not self.is_valid_new_block(current_block, previous_block):
                print(f"Block {current_block.index} không hợp lệ trong chuỗi được nhận.")
                return False
            temp_state_db.apply_block(current_block) # Apply to temp state for validation
        return True
    
    def rebuild_state(self):
        """Rebuilds the entire state database from the current blockchain."""
        self.state_db = StateDB() # Reset state
        for block in self.chain:
            self.state_db.apply_block(block)
        print("[Blockchain] Đã xây dựng lại trạng thái từ chuỗi.")
    
    def get_state_snapshot(self) -> bytes:
        """Returns a compressed snapshot of the current state."""
        state_json = json.dumps({
            "balances": dict(self.state_db.balances),
            "did_registry": self.state_db.did_registry
        })
        return zlib.compress(state_json.encode('utf-8'))

    def load_state_snapshot(self, snapshot_bytes: bytes):
        """Loads state from a compressed snapshot."""
        state_json = zlib.decompress(snapshot_bytes).decode('utf-8')
        state_data = json.loads(state_json)
        self.state_db.balances = defaultdict(float, state_data["balances"])
        self.state_db.did_registry = state_data["did_registry"]
        print("[Blockchain] Đã tải trạng thái từ snapshot.")
    
    def add_transaction_to_mempool(self, transaction: 'Transaction') -> bool: # 'Transaction' for forward reference
        """
        Adds a transaction to the mempool after basic validation.
        Returns True if added successfully, False otherwise.
        """
        if not isinstance(transaction, Transaction):
            print("[Mempool] Lỗi: Đối tượng không phải là Transaction.")
            return False

        if transaction.txid in self.mempool:
            print(f"[Mempool] Giao dịch {transaction.txid[:10]}... đã tồn tại trong mempool.")
            return False

        self.mempool[transaction.txid] = transaction
        print(f"[Mempool] Đã thêm giao dịch {transaction.txid[:10]}... vào mempool. Tổng số giao dịch: {len(self.mempool)}")
        return True
    
    def apply_block(self, block) -> bool:
        try:
            # Áp dụng giao dịch vào StateDB
            success = self.state_db.apply_transactions(block.transactions)
            if not success:
                print("[Blockchain] Lỗi khi áp dụng block vào trạng thái. Block không được thêm.")
                return False

            # Nếu có các giao dịch CROSS_TRANSFER cần gửi RECEIVE_TRANSFER
            if hasattr(self.state_db, "cross_shard_messages"):
                for to_shard, receive_tx in self.state_db.cross_shard_messages:
                    asyncio.create_task(
                        self.p2p_node.send_to_shard({
                            "type": "TRANSACTION",
                            "transaction": receive_tx.to_dict()
                        }, target_shard=to_shard)
                    )
                    print(f"[Blockchain] 📤 Đã gửi RECEIVE_TRANSFER sang shard {to_shard}")
                self.state_db.cross_shard_messages.clear()
            return True
        except Exception as e:
            print(f"[Blockchain] ❌ Lỗi khi apply_block: {e}")
            return False
        
    def set_p2p_node(self, p2p_node):
        self.p2p_node = p2p_node

    def get_validator_ids_for_shard(self, shard_id: int):
        return self.validator_shards.get(shard_id, [])

# =============================================================================
# D-BFT Consensus
# =============================================================================
# Trong vietid17.py, bên trong class D_BFT_Consensus:
class D_BFT_Consensus:
    def __init__(self, node_id: str, blockchain, p2p_node,
                 is_primary: bool,
                 validator_private_key_ecc: SigningKey,
                 validator_public_key_ecc: VerifyingKey,
                 validators: list[str],
                 view_timeout: int = 10, tx_batch_size: int = 3):
        
        self.node_id = node_id
        self.is_primary = is_primary # True if this node is the current primary
        self.blockchain = blockchain
        self.validator_id = node_id
        self.current_view = 0
        self.current_proposed_block = None
        self.p2p_node = p2p_node 
        self.validators = sorted(validators)
        self.validator_public_keys_ecc = {
            # Khởi tạo với public key của node hiện tại
            self.node_id: validator_public_key_ecc
        }
        # TODO: Trong một hệ thống thực tế, bạn cần trao đổi/tải public keys cho tất cả các validator khác.

        self.validator_private_key_ecc = validator_private_key_ecc # Khóa riêng ECC để ký tin nhắn đồng thuận
        self.validator_public_key_ecc = validator_public_key_ecc # Khóa công khai ECC để ký tin nhắn đồng thuận

        self.sequence_number = self.blockchain.get_latest_block().index + 1 # Chỉ số block hiện tại để đề xuất
        self.view_number = 0 # Số lượt xem hiện tại

        self.primary_validator_id = self._get_primary_for_view(self.view_number)
        self.pre_prepare_messages = defaultdict(dict)
        self.prepare_messages = defaultdict(lambda: defaultdict(dict))
        self.commit_messages = defaultdict(lambda: defaultdict(dict))
        self.replies = defaultdict(list)

        self.view_timeout = view_timeout
        self.view_timer = None
        self.tx_batch_size = tx_batch_size

        self.consensus_loop_task = None
        self.invalid_tx_warning_printed = False
        self.empty_mempool_warning_printed = False

    def _get_primary_for_view(self, view_number: int) -> str:
        if not self.validators:
            raise ValueError("Danh sách validators không được rỗng.")

        # Lấy danh sách validator IDs (self.validators đã là một list được sắp xếp)
        validator_ids = self.validators 
        
        # Tính toán chỉ số của primary validator dựa trên view_number
        primary_index = view_number % len(validator_ids)
        
        return validator_ids[primary_index]

    # Lọc giao dịch CROSS_TRANSFER chỉ lấy từ shard hiện tại
    def _filter_transactions_for_shard(self, transactions, shard_id):
        filtered = []
        for tx in transactions:
            if tx.tx_type == "CROSS_TRANSFER":
                try:
                    tx_data = json.loads(tx.data)
                    from_shard = tx_data.get("from_shard")
                    if from_shard == shard_id:
                        filtered.append(tx)
                    else:
                        print(f"[Filter] ⏩ Bỏ CROSS_TRANSFER từ shard {from_shard}, không phải shard hiện tại {shard_id}")
                except Exception as e:
                    print(f"[Filter] ❌ Lỗi khi phân tích CROSS_TRANSFER: {e}")
            else:
                filtered.append(tx)
        return filtered


    async def _propose_block(self):
        # Lấy tất cả giao dịch từ mempool
        all_transactions = list(self.blockchain.mempool.values())

        # Lọc theo shard_id
        filtered_transactions = self._filter_transactions_for_shard(all_transactions, self.blockchain.shard_id)

        # Lọc các giao dịch hợp lệ bằng simulate_transaction
        valid_transactions = []
        for tx in filtered_transactions:
            if self.blockchain.state_db.simulate_transaction(tx):
                valid_transactions.append(tx)
            if not self.invalid_tx_warning_printed:
                print(f"[D-BFT] ⚠️ Bỏ qua giao dịch không hợp lệ: {tx.txid[:10]}...")
                self.invalid_tx_warning_printed = True

        # Giới hạn theo batch size
        transactions_to_include = valid_transactions[:self.tx_batch_size]


        if not transactions_to_include:
            if not self.empty_mempool_warning_printed:
                print("[D-BFT] Mempool trống, không có giao dịch để đề xuất block.")
                self.empty_mempool_warning_printed = True
            return
        else:
            self.empty_mempool_warning_printed = False
            self.invalid_tx_warning_printed = False
            print(f"[D-BFT] Primary {self.validator_id} đang đề xuất block {self.sequence_number} với {len(self.blockchain.mempool)} giao dịch.")

        new_block = Block(
            index=self.blockchain.get_latest_block().index + 1,
            transactions=transactions_to_include,
            timestamp=datetime.now(timezone.utc).isoformat(),
            previous_hash=self.blockchain.get_latest_block().hash,
            validator_id=self.validator_id,
            view_number=self.current_view,
            sequence_number=self.sequence_number,
            nonce=0, # Giữ nguyên nếu nonce luôn là 0 hoặc tính toán khác nếu cần
            shard_id=self.blockchain.shard_id 
        )

        block_hash = new_block.hash

        # Ký block hash bằng khóa riêng của validator
        block_signature = schnorr_sign(self.validator_private_key_ecc, block_hash.encode('utf-8'))
        new_block.signature = block_signature # Gán chữ ký vào block

        self.current_proposed_block = new_block

        # Tạo tin nhắn PRE-PREPARE
        pre_prepare_message = {
            "type": "CONSENSUS",
            "subtype": "PRE_PREPARE",
            "sender_id": self.validator_id,
            "view_number": self.current_view,
            "sequence_number": self.sequence_number,
            "primary_id": self.node_id,
            "block": new_block.to_dict(), # SỬ DỤNG PHƯƠNG THỨC to_dict() Ở ĐÂY
            "block_hash": block_hash,
            "block_signature": block_signature.hex(), # Chuyển bytes chữ ký thành hex string
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Lưu trữ tin nhắn PRE-PREPARE
        self.pre_prepare_messages[self.sequence_number][self.validator_id] = pre_prepare_message

        # Gửi tin nhắn PRE-PREPARE đến tất cả các replica
        await self.p2p_node.broadcast_message(pre_prepare_message)
        print(f"[D-BFT] Đã gửi PRE-PREPARE cho block {self.sequence_number}. Hash: {block_hash[:10]}...")

        # Chuyển sang giai đoạn PREPARE (Primary tự động chuyển)
        await self._send_prepare_after_pre_prepare(new_block)

    async def _send_prepare_after_pre_prepare(self, block):
        """
        Giai đoạn PREPARE: Primary tự động gửi tin nhắn PREPARE cho block đã đề xuất.
        """
        print(f"[D-BFT] Primary {self.validator_id} đang tự động gửi tin nhắn PREPARE cho block {block.sequence_number}. Hash: {block.hash[:10]}...")

        # Tạo chuỗi dữ liệu chuẩn hóa để ký tin nhắn PREPARE
        prepare_data_string = (
            f"{self.current_view}"
            f"{self.sequence_number}"
            f"{block.hash}"
            f"{self.validator_id}"
            f"PREPARE" 
        )
        prepare_message_hash = hash_message(prepare_data_string.encode('utf-8'))
        prepare_signature = schnorr_sign(self.validator_private_key_ecc, prepare_message_hash)

        prepare_message = {
            "type": "CONSENSUS",
            "subtype": "PREPARE",
            "sender_id": self.validator_id,
            "view_number": self.current_view,
            "sequence_number": self.sequence_number,
            "block_hash": block.hash,
            "validator_id": self.node_id,
            "signature": prepare_signature.hex(), # Chữ ký của tin nhắn PREPARE
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Lưu trữ tin nhắn PREPARE của chính primary
        self.prepare_messages[self.sequence_number][block.hash][self.validator_id] = prepare_message

        # Gửi tin nhắn PREPARE đến tất cả các replica
        await self.p2p_node.broadcast_message(prepare_message)
        print(f"[D-BFT] Đã gửi tin nhắn PREPARE cho block {block.sequence_number}. Hash: {block.hash[:10]}...")

        # Sau khi gửi PREPARE, primary cũng cần kiểm tra quorum PREPARE (bao gồm cả chính nó)
        # để chuyển sang giai đoạn COMMIT.
        await self._check_prepare_quorum_and_send_commit(block.hash) # Sẽ định nghĩa ở bước tiếp theo

    async def _check_prepare_quorum_and_send_commit(self, block_hash: str):
        """
        Kiểm tra xem đã nhận đủ tin nhắn PREPARE cho một block cụ thể chưa.
        Nếu đủ, gửi tin nhắn COMMIT.
        """
        print(f"[D-BFT] Kiểm tra quorum PREPARE cho block {self.sequence_number} (hash: {block_hash[:10]})...")
        
        num_validators = len(self.validators)
        # Quorum đơn giản: (Tổng số validator / 2) + 1
        # Ví dụ: 3 validator -> (3/2) + 1 = 1 + 1 = 2
        # Ví dụ: 4 validator -> (4/2) + 1 = 2 + 1 = 3
        quorum_count = (num_validators // 2) + 1 

        current_prepares = self.prepare_messages[self.sequence_number].get(block_hash, {})
        num_prepares = len(current_prepares)

        print(f"[D-BFT] Đã nhận {num_prepares} tin nhắn PREPARE cho block {self.sequence_number}/{block_hash[:10]}. Quorum cần: {quorum_count}")

        if num_prepares >= quorum_count:
            print(f"[D-BFT] Đã đạt quorum PREPARE cho block {self.sequence_number} (hash: {block_hash[:10]}).")

            # Tạo tin nhắn COMMIT
            commit_data_string = (
                f"{self.current_view}"
                f"{self.sequence_number}"
                f"{block_hash}"
                f"{self.validator_id}"
                f"COMMIT" 
            )
            commit_message_hash = hash_message(commit_data_string.encode('utf-8'))
            commit_signature = schnorr_sign(self.validator_private_key_ecc, commit_message_hash)

            commit_message = {
                "type": "CONSENSUS",
                "subtype": "COMMIT",
                "sender_id": self.validator_id,
                "view_number": self.current_view,
                "sequence_number": self.sequence_number,
                "block_hash": block_hash,
                "validator_id": self.node_id,
                "signature": commit_signature.hex(), 
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

            # Lưu trữ tin nhắn COMMIT của chính primary
            self.commit_messages[self.sequence_number][block_hash][self.validator_id] = commit_message

            # Gửi tin nhắn COMMIT đến tất cả các replica
            await self.p2p_node.broadcast_message(commit_message)
            print(f"[D-BFT] Đã gửi tin nhắn COMMIT cho block {self.sequence_number}. Hash: {block_hash[:10]}...")

            # Sau khi gửi COMMIT, primary cũng cần kiểm tra quorum COMMIT để thêm block vào blockchain.
            await self._check_commit_quorum_and_add_block(block_hash) # Sẽ định nghĩa ở bước tiếp theo

    async def _check_commit_quorum_and_add_block(self, block_hash: str):
        """
        Kiểm tra xem đã nhận đủ tin nhắn COMMIT cho một block cụ thể chưa.
        Nếu đủ, commit block vào blockchain.
        """
        print(f"[D-BFT] Kiểm tra quorum COMMIT cho block {self.sequence_number} (hash: {block_hash[:10]})...")

        num_validators = len(self.validators)
        quorum_count = (num_validators // 2) + 1 # Quorum đơn giản

        current_commits = self.commit_messages[self.sequence_number].get(block_hash, {})
        num_commits = len(current_commits)

        print(f"[D-BFT] Đã nhận {num_commits} tin nhắn COMMIT cho block {self.sequence_number}/{block_hash[:10]}. Quorum cần: {quorum_count}")

        if num_commits >= quorum_count:
            print(f"[D-BFT] Đã đạt quorum COMMIT cho block {self.sequence_number} (hash: {block_hash[:10]}).")
            
            # Đảm bảo chúng ta có block object để thêm vào blockchain.
            # Primary đã lưu trữ block này trong self.current_proposed_block.
            if self.current_proposed_block and \
               self.current_proposed_block.hash == block_hash and \
               self.current_proposed_block.sequence_number == self.sequence_number:
                
                print(f"[D-BFT] Primary {self.validator_id} đang thêm block {self.current_proposed_block.sequence_number} vào chuỗi...")
                if self.blockchain.add_block(self.current_proposed_block):
                    print(f"[D-BFT] Block {self.current_proposed_block.sequence_number} (hash: {block_hash[:10]}) đã được thêm thành công vào chuỗi của Primary.")
                    self.sequence_number += 1 # Tăng sequence number cho block tiếp theo
                    self.last_block_committed_time = time.time() # Cập nhật thời gian commit
                    
                    # Xóa các tin nhắn đồng thuận đã cũ sau khi block được commit
                    self.pre_prepare_messages.pop(self.sequence_number - 1, None)
                    self.prepare_messages.pop(self.sequence_number - 1, None)
                    self.commit_messages.pop(self.sequence_number - 1, None)
                    
                    self.blockchain.mempool.clear() # Xóa mempool sau khi block được thêm vào
                    self.current_proposed_block = None # Đặt lại block đề xuất hiện tại
                else:
                    print(f"[D-BFT] Lỗi khi thêm block {self.current_proposed_block.sequence_number} vào chuỗi của Primary.")
            else:
                print(f"[D-BFT] Primary không tìm thấy block phù hợp để commit với hash {block_hash[:10]} và sequence {self.sequence_number}. Điều này không nên xảy ra.")
        
    async def handle_pre_prepare(self, message: dict):
        try:
            view_num = message["view_number"]
            seq_num = message["sequence_number"]
            primary_id = message["primary_id"]
            block_dict = message["block"]
            block_hash_from_msg = message["block_hash"]
        except KeyError as e:
            print(f"[D-BFT] ❌ Thiếu trường trong PRE_PREPARE: {e}")
            return

        if view_num is None or seq_num is None or not primary_id or not block_dict or not block_hash_from_msg:
            print("[D-BFT] ❌ PRE_PREPARE thiếu một số trường cần thiết.")
            return
        '''
        if seq_num <= self.blockchain.get_latest_block().index:
            print(f"[D-BFT] Bỏ qua PRE_PREPARE cho block {seq_num} vì block đã cũ.")
            return
        '''
        latest_index = self.blockchain.get_latest_block().index
        if seq_num <= latest_index:
            existing_block = self.blockchain.get_block_by_index(seq_num)
            if existing_block and existing_block.hash == block_hash_from_msg:
                print(f"[D-BFT] Bỏ qua PRE_PREPARE cho block {seq_num} vì đã có block giống hệt.")
                return
            else:
                print(f"[⚠️ D-BFT] Phát hiện xung đột block tại index {seq_num}:")
                print(f"  - Block cũ: {existing_block.hash[:10]}...")
                print(f"  - Block mới từ primary: {block_hash_from_msg[:10]}...")
                # Tùy chiến lược: có thể đánh dấu để VIEW_CHANGE
                return

        if primary_id != self._get_primary_for_view(view_num):
            print(f"[D-BFT] Lỗi: PRE_PREPARE từ primary không hợp lệ ({primary_id} thay vì {self._get_primary_for_view(view_num)})")
            return

        if seq_num in self.pre_prepare_messages and primary_id in self.pre_prepare_messages[seq_num]:
            print(f"[D-BFT] Đã nhận PRE_PREPARE cho seq {seq_num} từ primary {primary_id}. Bỏ qua.")
            return # Already received this PRE_PREPARE

        self.pre_prepare_messages[seq_num][primary_id] = message

        block = Block.from_dict(block_dict)

        # Verify block integrity and primary's signature
        if block.calculate_hash() != block.hash or block.hash != block_hash_from_msg:
            print(f"[D-BFT] Lỗi: Hash block trong PRE_PREPARE không khớp hoặc không hợp lệ. {block.calculate_hash()[:10]} vs {block.hash[:10]} vs {block_hash_from_msg[:10]}")
            return
        
        # Verify primary's signature on the block
        if not self.verify_block_signature(block):
            print(f"[D-BFT] Lỗi: Chữ ký block trong PRE_PREPARE từ primary {primary_id} không hợp lệ.")
            return

        # Check if previous block is valid and exists in chain
        if block.index != self.blockchain.get_latest_block().index + 1 or \
           block.previous_hash != self.blockchain.get_latest_block().hash:
            print(f"[D-BFT] Lỗi: Block trong PRE_PREPARE không liên kết với chuỗi hiện tại. Index {block.index}, PrevHash {block.previous_hash[:10]}...")
            # This is a critical error, might trigger view change later
            return

        # Validate transactions in the block (if they are in mempool, or valid new ones)
        # For simplicity, we just check signature here. More complex validation could be added.
        for tx in block.transactions:
            if not tx.verify_signature():
                print(f"[D-BFT] Lỗi: Giao dịch {tx.txid[:10]}... trong block PRE_PREPARE có chữ ký không hợp lệ.")
                return # Do not proceed if any transaction is invalid

        print(f"[D-BFT] Nhận PRE_PREPARE hợp lệ cho block {seq_num} (hash: {block_hash_from_msg[:10]}...) từ primary {primary_id}. Gửi PREPARE.")
        
        prepare_message = {
            "type": "CONSENSUS",
            "subtype": "PREPARE",
            "view_number": view_num,
            "sequence_number": seq_num,
            "block_hash": block_hash_from_msg,
            "validator_id": self.node_id,
            "signature": schnorr_sign(self.validator_private_key_ecc, hash_message(f"PREPARE_{view_num}_{seq_num}_{block_hash_from_msg}".encode('utf-8')))
        }
        await self.p2p_node.broadcast_message(prepare_message)
        await self.handle_prepare(prepare_message) # Process locally as well

    async def handle_prepare(self, message: dict):
        try:
            view_num = message["view_number"]
            seq_num = message["sequence_number"]
            block_hash = message["block_hash"]
            validator_id = message["validator_id"]
            signature = message["signature"]
        except KeyError as e:
            print(f"[D-BFT] ❌ Thiếu trường trong PREPARE: {e}")
            return
        
        if seq_num <= self.blockchain.get_latest_block().index:
            return

        # Verify signature
        if validator_id not in self.validator_public_keys_ecc:
            print(f"[D-BFT] Lỗi: PREPARE từ validator không xác định: {validator_id}.")
            return
        
        message_to_verify = f"PREPARE_{view_num}_{seq_num}_{block_hash}".encode('utf-8')
        if not schnorr_verify(self.validator_public_keys_ecc[validator_id], hash_message(message_to_verify), signature):
            print(f"[D-BFT] Lỗi: Chữ ký PREPARE từ {validator_id} không hợp lệ.")
            return

        self.prepare_messages[seq_num][block_hash].add(validator_id)
        print(f"[D-BFT] Nhận PREPARE hợp lệ cho block {seq_num} (hash: {block_hash[:10]}...) từ {validator_id}.")

        # Check for 2f + 1 PREPARE messages
        num_validators = len(self.validators)
        required_prepares = 2 * (num_validators // 3) + 1 # At least 2/3 + 1 for Byzantine Fault Tolerance
        if len(self.prepare_messages[seq_num][block_hash]) >= required_prepares:
            print(f"[D-BFT] Đạt {required_prepares} PREPARE cho block {seq_num} (hash: {block_hash[:10]}...). Gửi COMMIT.")
            commit_message = {
                "type": "CONSENSUS",
                "subtype": "COMMIT",
                "view_number": view_num,
                "sequence_number": seq_num,
                "block_hash": block_hash,
                "validator_id": self.node_id,
                "signature": schnorr_sign(self.validator_private_key_ecc, hash_message(f"COMMIT_{view_num}_{seq_num}_{block_hash}".encode('utf-8')))
            }
            await self.p2p_node.broadcast_message(commit_message)
            await self.handle_commit(commit_message) # Process locally as well

    async def _send_prepare(self, block_hash: str, view_number: int, sequence_number: int):
        """
        Gửi tin nhắn PREPARE từ Replica sau khi nhận và xác thực PRE_PREPARE.
        """
        print(f"[D-BFT][REPLICA] {self.validator_id} đang gửi tin nhắn PREPARE cho block {sequence_number}. Hash: {block_hash[:10]}...")

        prepare_data_string = (
            f"{view_number}"
            f"{sequence_number}"
            f"{block_hash}"
            f"{self.validator_id}"
            f"PREPARE"
        )
        prepare_message_hash = hash_message(prepare_data_string.encode('utf-8'))
        prepare_signature = schnorr_sign(self.validator_private_key_ecc, prepare_message_hash)

        prepare_message = {
            "type": "CONSENSUS",
            "subtype": "PREPARE",
            "sender_id": self.validator_id,
            "view_number": view_number,
            "sequence_number": sequence_number,
            "block_hash": block_hash,
            "validator_id": self.node_id,
            "signature": prepare_signature.hex(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Lưu trữ tin nhắn PREPARE của chính Replica
        self.prepare_messages[sequence_number][block_hash][self.validator_id] = prepare_message

        await self.p2p_node.broadcast_message(prepare_message)
        print(f"[D-BFT][REPLICA] Đã gửi tin nhắn PREPARE cho block {sequence_number}.")

        # Sau khi gửi PREPARE, Replica cũng cần kiểm tra quorum PREPARE
        await self._check_prepare_quorum_and_send_commit(block_hash)

    def _get_public_key_for_validator(self, validator_id: str) -> bytes:
        """
        Phương thức giả định để lấy public key PEM của một validator dựa trên ID của họ.
        Trong thực tế, bạn sẽ có một danh sách các public key của validator được cấu hình trước
        hoặc được truy xuất từ một dịch vụ đáng tin cậy.
        """
        # Đây là ví dụ đơn giản, bạn cần có một cách đáng tin cậy để ánh xạ validator_id đến public key của họ
        # Ví dụ:
        # Nếu node_id là "node_1_id_example_for_dbft" thì public_key_pem là "node_1_pub_key.pem"
        # Node 1
        if validator_id == "node_1_id_example_for_dbft":
            try:
                with open("node_1_pub_key.pem", "rb") as f:
                    return f.read()
            except FileNotFoundError:
                print(f"Lỗi: Không tìm thấy node_1_pub_key.pem cho validator {validator_id}")
                return None
        # Node 2
        elif validator_id == "node_2_id_example_for_dbft":
            try:
                with open("node_2_pub_key.pem", "rb") as f:
                    return f.read()
            except FileNotFoundError:
                print(f"Lỗi: Không tìm thấy node_2_pub_key.pem cho validator {validator_id}")
                return None
        # Node 3 (Nếu có)
        elif validator_id == "node_3_id_example_for_dbft":
            try:
                with open("node_3_pub_key.pem", "rb") as f:
                    return f.read()
            except FileNotFoundError:
                print(f"Lỗi: Không tìm thấy node_3_pub_key.pem cho validator {validator_id}")
                return None
        else:
            return None # Validator không xác định hoặc không có public key


    async def handle_commit(self, message: dict):
        try:
            view_num = message["view_number"]
            seq_num = message["sequence_number"]
            block_hash = message["block_hash"]
            validator_id = message["validator_id"]
            signature = message["signature"]
        except KeyError as e:
            print(f"[D-BFT] ❌ Thiếu trường trong COMMIT: {e}")
            return

        if seq_num <= self.blockchain.get_latest_block().index:
            return

        # Verify signature
        if validator_id not in self.validator_public_keys_ecc:
            print(f"[D-BFT] Lỗi: COMMIT từ validator không xác định: {validator_id}.")
            return

        message_to_verify = f"COMMIT_{view_num}_{seq_num}_{block_hash}".encode('utf-8')
        if not schnorr_verify(self.validator_public_keys_ecc[validator_id], hash_message(message_to_verify), signature):
            print(f"[D-BFT] Lỗi: Chữ ký COMMIT từ {validator_id} không hợp lệ.")
            return

        self.commit_messages[seq_num][block_hash].add(validator_id)
        print(f"[D-BFT] Nhận COMMIT hợp lệ cho block {seq_num} (hash: {block_hash[:10]}...) từ {validator_id}.")

        # Check for 2f + 1 COMMIT messages
        num_validators = len(self.validators)
        required_commits = 2 * (num_validators // 3) + 1 # At least 2/3 + 1
        if len(self.commit_messages[seq_num][block_hash]) >= required_commits:
            print(f"[D-BFT] Đạt {required_commits} COMMIT cho block {seq_num} (hash: {block_hash[:10]}...).")

            # Finalize the block
            # Retrieve the full block from the stored pre-prepare message
            pre_prepare_msg = self.pre_prepare_messages[seq_num].get(self._get_primary_for_view(view_num))
            if pre_prepare_msg and pre_prepare_msg["block_hash"] == block_hash:
                final_block = Block.from_dict(pre_prepare_msg["block"])
                
                if self.blockchain.add_block(final_block):
                    print(f"[D-BFT] Đã cam kết block {seq_num} (hash: {final_block.hash[:10]}...) thành công!")
                    self.sequence_number += 1 # Move to the next sequence number
                    self.view_number += 1 # Move to the next view (could be reset on primary change)
                    self.primary_validator_id = self._get_primary_for_view(self.view_number)
                    self.is_primary = (self.node_id == self.primary_validator_id)
                    print(f"[D-BFT] Primary tiếp theo cho view {self.view_number} là: {self.primary_validator_id}.")

                    # Clean up messages for this sequence number
                    self.pre_prepare_messages.pop(seq_num, None)
                    self.prepare_messages.pop(seq_num, None)
                    self.commit_messages.pop(seq_num, None)
                else:
                    print(f"[D-BFT] Lỗi: Không thể thêm block {seq_num} vào chuỗi sau khi đạt COMMIT.")
            else:
                print(f"[D-BFT] Lỗi: Không tìm thấy PRE_PREPARE message cho block {seq_num} với hash {block_hash[:10]} để cam kết.")

    def verify_block_signature(self, block: Block) -> bool:
        """Verifies the signature of a block using the validator's ECC public key."""
        if not block.signature:
            print(f"[D-BFT] Lỗi xác minh block: Không có chữ ký cho block {block.index}.")
            return False
        if block.validator_id not in self.validator_public_keys_ecc:
            print(f"[D-BFT] Lỗi xác minh block: Validator ID {block.validator_id} không xác định hoặc không có public key.")
            return False

        public_key = self.validator_public_keys_ecc[block.validator_id]
        message_hash = hash_message(block.to_string_for_signing().encode('utf-8'))
        return schnorr_verify(public_key, message_hash, block.signature)

    async def run_consensus_loop(self):
        print(f"[D-BFT] Node {self.node_id} bắt đầu vòng lặp đồng thuận. Primary hiện tại: {self.primary_validator_id}.")
        self.consensus_loop_task = asyncio.create_task(self._consensus_loop_internal())

    async def _consensus_loop_internal(self):
        while True:
            try:
                await asyncio.sleep(1) # Small delay to prevent busy-waiting

                # Periodically check if this node should be the primary
                current_primary = self._get_primary_for_view(self.view_number)
                if self.primary_validator_id != current_primary:
                    print(f"[D-BFT] Chuyển primary: {self.primary_validator_id} -> {current_primary}. Cập nhật view number lên {self.view_number}.")
                    self.primary_validator_id = current_primary
                    self.is_primary = (self.node_id == self.primary_validator_id)
                    # Reset consensus state for the new view if needed, or clear old messages
                    self.pre_prepare_messages.clear()
                    self.prepare_messages.clear()
                    self.commit_messages.clear()
                    # A proper view change mechanism would be more complex, involving voting for new primary

                self.is_primary = (self.node_id == self.primary_validator_id) # Re-evaluate is_primary

                # If primary and haven't proposed for current sequence number
                # and there are transactions in mempool
                if self.is_primary and self.blockchain.mempool and \
                   (self.sequence_number > self.blockchain.get_latest_block().index) and \
                   (self.sequence_number not in self.pre_prepare_messages or \
                    self.primary_validator_id not in self.pre_prepare_messages[self.sequence_number]):
                    
                    # Add a small delay to avoid proposing too fast and give time for network sync
                    # before a new proposal is initiated.
                    await asyncio.sleep(2) 
                    # Double check conditions after sleep to ensure no race condition
                    if self.is_primary and self.blockchain.mempool and \
                       (self.sequence_number > self.blockchain.get_latest_block().index) and \
                       (self.sequence_number not in self.pre_prepare_messages or \
                        self.primary_validator_id not in self.pre_prepare_messages[self.sequence_number]):
                        await self._propose_block()
                
            except asyncio.CancelledError:
                print("[D-BFT] Consensus loop cancelled. Shutting down.")
                break # Exit the loop cleanly on shutdown
            except Exception as e:
                print(f"[D-BFT] Lỗi trong vòng lặp đồng thuận: {e}")
                # Optional: Add a small delay before retrying to prevent rapid error looping
                await asyncio.sleep(5) 

