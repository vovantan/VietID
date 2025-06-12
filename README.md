# VietID: Blockchain Layer-1 Vietnam

VietID là một nền tảng Blockchain Layer-1 thuần Việt, 
hướng đến phục vụ các ứng dụng định danh số, giao dịch minh bạch, 
công chứng điện tử và tích hợp các dịch vụ công trong quá trình chuyển đổi số quốc gia.

## 🚀 Tính năng chính
- ✅ Consensus DBFT (Delegated Byzantine Fault Tolerance)
- 🧱 Hệ thống Shard độc lập, hỗ trợ Cross-shard Transaction
- 🆔 DID (Decentralized Identifier) theo chuẩn W3C
- 🔐 Ký số ECC + Schnorr Signature
- 📡 Giao tiếp mạng P2P bảo mật bằng WebSocket + TLS
- 🔁 API RESTful mở: gửi giao dịch, truy vấn số dư, DID, block
- 💾 Snapshot trạng thái blockchain dạng nén nhẹ (zlib)

## 🧩 Kiến trúc hệ thống
```
+-----------------------------+
|     REST API (Flask)       |
+-----------------------------+
|    Blockchain Core (DBFT)  |
|  - Transaction, Block, VM  |
+-----------------------------+
|      P2P Node (asyncio)    |
+-----------------------------+
|       StateDB, Snapshot    |
+-----------------------------+
```

## 🛠 Cài đặt
### 1. Yêu cầu hệ thống
- Python >= 3.10
- OpenSSL & ECDSA
- Flask & Websocket

### 2. Cài đặt thư viện
```bash
pip install -r requirements.txt
```

### 3. Khởi tạo Node
```bash
python run_node1.py  # hoặc run_node2.py, run_node3.py
```

### 4. Giao diện API (cổng 5000)
```bash
curl http://localhost:5000/status
curl http://localhost:5000/balance/<address>
```

## 📦 Cấu trúc thư mục
```
├── vietid17.py          # Lõi blockchain
├── p2p_node.py         # Giao tiếp P2P
├── api_server.py       # API REST Flask
├── run_nodeX.py        # File khởi chạy node cụ thể
├── requirements.txt    # Danh sách thư viện
└── README.md           # Tài liệu này
```

## 📡 Danh sách API REST
| Method | Endpoint                              | Mô tả |
|--------|----------------------------------------|------|
| GET    | `/status`                             | Trạng thái node và blockchain |
| GET    | `/block/latest`                       | Block mới nhất |
| GET    | `/blocks/recent/<count>`              | Lấy `count` block gần nhất |
| GET    | `/block/<hash hoặc index>`            | Truy vấn block cụ thể |
| GET    | `/balance/<address>`                  | Tra số dư ví |
| GET    | `/did/list`                           | Danh sách tất cả DID đã đăng ký |
| GET    | `/did/<did>`                          | Truy vấn thông tin DID cụ thể |
| GET    | `/mempool`                            | Giao dịch đang chờ xử lý |
| GET    | `/tx/<txid>`                          | Truy vấn thông tin giao dịch cụ thể |
| GET    | `/governance/proposals`               | Danh sách đề xuất đang được bỏ phiếu |
| GET    | `/governance/votes/<proposal_id>`     | Chi tiết kết quả bỏ phiếu |
| POST   | `/tx/send`                            | Gửi giao dịch `TRANSFER` |
| POST   | `/tx/send/DID`                        | Gửi giao dịch `DID_REGISTER` |
| POST   | `/tx/send/VOTE`                       | Gửi giao dịch `VOTE` |
| POST   | `/tx/send/MINT`                       | Gửi giao dịch `MINT` token |

## 📥 Mẫu gửi giao dịch bằng curl

### Giao dịch TRANSFER (chuyển token)
```bash
curl -X POST http://localhost:5000/tx/send \
     -H "Content-Type: application/json" \
     -d '{
           "recipient": "<recipient_public_key_hex>",
           "amount": 100
         }'
```

### Giao dịch DID_REGISTER (đăng ký định danh số)
```bash
curl -X POST http://localhost:5000/tx/send/DID \
     -H "Content-Type: application/json" \
     -d '{
           "alias": "Tên hiển thị hoặc biệt danh"
         }'
```

### Giao dịch MINT (phát hành token mới)
```bash
curl -X POST http://localhost:5000/tx/send/MINT \
     -H "Content-Type: application/json" \
     -d '{
           "recipient": "<recipient_public_key_hex>",
           "amount": 1000
         }'
```

### Giao dịch VOTE (bỏ phiếu)
```bash
curl -X POST http://localhost:5000/tx/send/VOTE \
     -H "Content-Type: application/json" \
     -d '{
           "proposal_id": "prop-001",
           "vote": "YES"
         }'
```

### Giao dịch PROPOSE (đề xuất)
```bash
curl -X POST http://localhost:5000/tx/send/PROPOSE \
     -H "Content-Type: application/json" \
     -d '{
           "proposal_id": "prop-002",
           "title": "Tang gioi han block size",
           "description": "De xuat tang kich thuoc khoi tu 1MB len 2MB"
         }'
```

Lưu ý: - Nếu sử dụng Windows các dấu " của key: value phải được giải phóng bằng dấu \ ở trước phía trước,
value là chuỗi bằng Tiếng Việt sử dụng không dấu.
Ví dụ: curl -X POST http://localhost:5000/tx/send/DID -H "Content-Type: application/json" -d "{\"alias\": \"Tan\"}"

## 🔬 Demo
- Video demo: [link YouTube hoặc Google Drive nếu có]
- URL testnet (nếu public): đang xây dựng

## 🔒 License
MIT License - Mã nguồn mở, sử dụng tự do với điều kiện ghi nhận tác giả.

## 👥 Đội phát triển
- Võ Văn Tân – Kiến trúc, DBFT, API, DevOps
- Võ Thành Đại – P2P & bảo mật
- Trần Hồng Nhung – Pháp lý & tích hợp

## 📚 Tài liệu tham khảo
- [W3C DID Spec](https://www.w3.org/TR/did-core/)
- [Cosmos SDK Docs](https://docs.cosmos.network)
- [Tendermint Consensus](https://docs.tendermint.com)
- [RFC 7519 - JWT](https://datatracker.ietf.org/doc/html/rfc7519)

---

> Dự án được phát triển trong khuôn khổ cuộc thi Blockchain Layer-1 Việt Nam 2025. Mọi đóng góp, phản hồi và ý tưởng hợp tác đều được chào đón!
