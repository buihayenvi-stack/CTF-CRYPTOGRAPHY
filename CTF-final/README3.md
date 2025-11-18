"""
======================================================================
Một web API bị lỗi padding oracle → hacker gửi ciphertext → 
dựa vào phản hồi lỗi → trích xuất plaintext.

# Padding Oracle Attack - Cách thức hoạt động

## 1️⃣ Vấn đề cốt lõi
Padding Oracle Attack khai thác lỗ hổng trong việc xử lý padding 
của thuật toán mã hóa khối (như AES-CBC). Khi web API:
 - sử dụng **IV cố định** (fixed IV) thay vì IV ngẫu nhiên cho mỗi lần mã hóa, 
   và/hoặc
 - **trả thông báo lỗi khác nhau** cho padding hợp lệ và không hợp lệ,
thì kẻ tấn công có thể lợi dụng để từng byte khôi phục plaintext.

> **Lưu ý về IV cố định:** Nếu server luôn dùng cùng một IV (ví dụ `fixed_iv = b'FEDCBA...')`,
  attacker không chỉ biết IV gốc (vì IV thường được tiền tố vào ciphertext), mà còn dễ dàng **thay đổi
  phần IV** trong ciphertext gửi tới endpoint để điều khiển quá trình decrypt — điều này hỗ trợ
  việc brute-force từng byte trong padding oracle attack.

## 2️⃣ Cách thức tấn công (tóm tắt)
Từ code trong `paddown.py` / `paddown_attack.py`, quy trình tấn công:
1. **Gửi ciphertext đã bị sửa** (attacker chỉnh IV hoặc block trước đó).
2. **Quan sát phản hồi** của API để biết padding có hợp lệ không.
3. **Thử 256 giá trị** cho từng byte (từ cuối lên) để tìm giá trị hợp lệ.
4. **Tính intermediate value** và từ đó **tái tạo plaintext**.

## 3️⃣ Ví dụ cụ thể từ code (vulnerable_encryption_service.py)
```python
def decrypt(self, ciphertext):
    cipher = AES.new(self.key, AES.MODE_CBC, IV=self.iv)  # <-- IV có thể là fixed_iv
    try:
        unpad(cipher.decrypt(ciphertext), 16)
    except ValueError:
        raise InvalidPadding("Invalid PKCS7 Padding")  # ← Lỗ hổng: trả lỗi rõ ràng
    return "Decryption successful!"
