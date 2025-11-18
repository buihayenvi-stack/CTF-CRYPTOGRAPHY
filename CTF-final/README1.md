# Challenge 1 — Reused XOR keystream

Mục đích: Minh họa rủi ro khi **tái sử dụng cùng một keystream** trong các hệ thống mã hóa XOR/stream cipher. Mục tiêu giáo dục/CTF: người học phải nhận ra kt tái sử dụng keystream dẫn tới việc `ct1 ^ ct2 = p1 ^ p2` và dùng kỹ thuật "crib-dragging" hoặc phân tích tần suất để khôi phục plaintext.

---

## Mô tả ngắn

Tập tin mã nguồn (`challenge1_reused_xor.py`) sinh một keystream cố định `key = b'supersecretkeystream'` và mã hóa nhiều plaintext bằng phép XOR byte-wise với cùng keystream đó. Khi cùng một keystream bị dùng cho nhiều bản tin, XOR hai ciphertext sẽ triệt tiêu keystream, dẫn đến:
ct1 ^ ct2 = (p1 ^ key) ^ (p2 ^ key) = p1 ^ p2


Từ `p1 ^ p2` attacker có thể dùng các phỏng đoán (cribs), kiến thức ngôn ngữ, hoặc phân tích tần suất để dần khôi phục các plaintext gốc.

---

## Nội dung file

File demo thực hiện:

- Tạo keystream cố định `key`.
- Tạo 3 plaintext mẫu.
- Mã hóa từng plaintext bằng `ct = plaintext XOR key`.
- In ciphertext ở dạng hex.
- In `ct1 ^ ct2` và dùng một "crib" (đoán) để phục hồi một phần của `message1`.
