# RSA Vulnerabilities Demo 
Mục tiêu: Minh hoạ các lỗ hổng phổ biến của RSA trong CTF và môi trường thực tế

---

## Mô tả ngắn
Tập tin `challenge2_rsa.py` chứa các mô phỏng và ví dụ minh họa cho bốn loại lỗ hổng/bài toán liên quan đến RSA:

1. Cube Root Attack (Textbook RSA, e = 3)
2. Bleichenbacher-style padding oracle (PKCS#1 v1.5) — demo minh họa interval narrowing
3. Coppersmith-style partial key exposure (ghi chú / placeholder; cần SageMath để thực thi đầy đủ)
4. Fermat factorization (prime yếu, p và q gần nhau)

---

## Nội dung chi tiết các phần trong mã

### 1. Cube Root Attack
- Hàm: `cube_root_attack()`
- Mục tiêu: Nếu hệ thống dùng textbook RSA (không dùng padding an toàn) với số mũ công khai nhỏ (ví dụ e = 3) và plaintext thỏa `m^e < N`, thì ciphertext `c = m^e` có thể được phục hồi bằng cách lấy căn bậc e nguyên của `c`.
- Điều kiện khai thác:
  - Không có padding an toàn (OAEP), chỉ textbook RSA.
  - e nhỏ, plaintext đủ nhỏ để `m^e < N`.
- Kết quả minh họa: giải mã trực tiếp plaintext (flag) mà không cần khóa riêng.

### 2. Bleichenbacher-style Padding Oracle (Demo)
- Hàm: `bleichenbacher_demo()`
- Mục tiêu: Minh họa ý tưởng tấn công dựa trên phản hồi khác biệt của server khi kiểm tra padding PKCS#1 v1.5.
- Điều kiện khai thác:
  - Sử dụng PKCS#1 v1.5 cho padding.
  - Server cho phép gửi ciphertext và trả về thông tin/response có thể phân biệt (hoặc oracle).
- Ghi chú: phiên bản trong mã là bản demo đơn giản hoá logic interval narrowing; để tấn công thực tế cần nhiều điều chỉnh và số lượng truy vấn lớn.

### 3. Coppersmith (Partial Key Exposure)
- Hàm: `coppersmith_attack()` (placeholder)
- Mục tiêu: Khi một phần (low bits) của một thừa số nguyên tố (p) bị rò rỉ, Coppersmith method (dựa trên LLL) có thể được dùng để khôi phục toàn bộ p nếu điều kiện nhỏ đủ thỏa.
- Yêu cầu thực tế: cần thư viện/sản phẩm hỗ trợ LLL và small-roots, ví dụ SageMath. Phần mã hiện tại giữ ở dạng mô tả/approx do không có Sage trong môi trường chạy nhanh.

### 4. Fermat Factorization
- Hàm: `fermat_factor()`
- Mục tiêu: Nếu hai số nguyên tố p và q quá gần nhau (|p - q| nhỏ), Fermat method tìm a, b sao cho `a^2 - N = b^2` và suy ra p, q.
- Điều kiện khai thác: p và q gần nhau; phương pháp không hiệu quả cho p, q phân bố ngẫu nhiên lớn.

---

## Hướng dẫn cài đặt và chạy

1. Chuẩn bị môi trường Python 3.8+.

2. Cài phụ thuộc cần thiết:
   - Nếu mã có phần cần `pycryptodome` (một số demo khác):  
     ```
     python -m pip install pycryptodome
     ```
   - Nếu muốn chạy các hàm phụ thuộc `sympy` (nếu còn dùng):  
     ```
     python -m pip install sympy
     ```
   - Lưu ý: Coppersmith full cần SageMath; không có trong pip.

3. Chạy chương trình:

4. Kết quả mong đợi (mô tả):
- Phần cube-root sẽ in ra các giá trị m thu được (ví dụ flag giả).
- Bleichenbacher demo in trạng thái thu hẹp interval (bản demo đơn giản).
- Coppersmith in cảnh báo/placeholder nếu SageMath không có.
- Fermat sẽ thử phân tích N yếu (nếu N yếu được cung cấp) và in p, q nếu thành công.

---

## Giải thích ngắn gọn về nguyên lý tấn công và biện pháp phòng chống

### Nguyên lý tấn công
- Cube Root: tận dụng textbook RSA khi không có padding; căn bậc e phục hồi plaintext nếu `m^e < N`.
- Bleichenbacher: tận dụng oracle trả về thông tin phân biệt về padding; attacker lặp truy vấn để thu hẹp khoảng chứa plaintext.
- Coppersmith: dùng lý thuyết đa thức và kỹ thuật LLL để tìm nghiệm nhỏ của đa thức modulo N; ứng dụng khi có partial key leak.
- Fermat: sử dụng phương pháp đại số đơn giản khi p và q quá gần nhau.

### Biện pháp phòng chống (thực tế)
1. Sử dụng padding an toàn: OAEP cho RSA-kem/enkryp.
2. Không tiết lộ chi tiết lỗi giải mã/không trả thông báo khác biệt cho lỗi padding.
3. Dùng prime đủ lớn, không dùng prime quá gần nhau.
4. Không để rò rỉ thông tin một phần của khóa; nếu cần, sử dụng các cơ chế bảo vệ key management.
5. Sử dụng authenticated encryption, xác thực đầu vào trước khi giải mã (MAC/HMAC, AEAD).
6. Giới hạn số lượng truy vấn / áp dụng rate limiting, logging để phát hiện hành vi bất thường.

---

## Hạn chế của demo
- Một số hàm là mô phỏng/giả lập nhằm mục đích học tập và không phản ánh đủ phức tạp thực tế.
- Coppersmith đầy đủ yêu cầu SageMath hoặc môi trường hỗ trợ LLL; phần mã hiện tại chỉ là placeholder/approx.
- Bleichenbacher thực tế yêu cầu điều chỉnh kỹ thuật interval narrowing và chạy nhiều truy vấn; demo đơn giản chỉ minh họa ý tưởng.

---

## Tài liệu tham khảo
- Daniel Bleichenbacher, "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1" (CRYPTO 1998).
- Don Coppersmith, "Small Solutions to Polynomial Equations, and Low Exponent RSA Vulnerabilities" (Eurocrypt 1996).
- Fermat factorization method (lịch sử phương pháp phân tích).
- Nhiều nguồn tài liệu CTF và đề luyện cryptography (CryptoHack, PicoCTF, v.v.) cho bài tập thực hành.

