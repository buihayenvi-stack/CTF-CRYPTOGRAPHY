Nghiên cứu các lỗ hổng mã hóa thường gặp trong bài thi Capture The Flag và cách khai thác. Ở đây mình thực hiện mô phỏng 3 challenge: Reuse-key XOR — lỗi xuất hiện trong truyền tin khi dùng lại khóa; (2) 4 loại lỗ hổng trong RSA; và AES-CBC padding oracle — lỗi sử dụng init value cố định và trả về lỗi rõ ràng, làm API khiến server vô tình tiết lộ thông tin.
—-------------------------------------------------------------------------------------------------------------------
challenge1_reused_xor.py, mô phỏng việc tái sử dụng cùng một keystream, đầu tiên sẽ sinh một keystream cố định và mã hóa nhiều plaintext bằng phép XOR với cùng keystream. Khi cùng một keystream bị dùng cho nhiều bản tin, XOR hai ciphertext sẽ triệt tiêu keystream, ta sẽ khôi phục được 2 plaintext
ct1 ^ ct2 = (p1 ^ key) ^ (p2 ^ key) = p1 ^ p2
Từ `p1 ^ p2` attacker có thể dùng các phỏng đoán (cribs), kiến thức ngôn ngữ, hoặc phân tích tần suất để dần khôi phục các plaintext gốc.
—------------------------------------------------------------------------------------------------------------------
Challenge thứ hai là tập hợp 4 loại lỗ hổng RSA thường gặp trong CTF.
Với Cube Root Attack, nếu hệ thống dùng textbook RSA và e = 3, attacker có thể giải mã trực tiếp bằng cách lấy căn bậc ba.
Với Bleichenbacher, nếu server phản hồi khác nhau khi padding sai, attacker có thể gửi hàng loạt ciphertext để thu hẹp khoảng chứa plaintext.
Coppersmith là kỹ thuật nâng cao, dùng khi một phần khóa bị rò rỉ — tuy nhiên cần môi trường hỗ trợ như SageMath.
Cuối cùng, Fermat khai thác sai lầm khi sinh khóa RSA khi p và q quá gần nhau.
—-------------------------------------------------------------------------------------------------------------------
vulnerable
Challenge cuối cùng là Padding Oracle Attack. Khi API dùng IV cố định và trả lỗi rõ ràng khi padding sai, attacker có thể sửa ciphertext và brute-force từng byte để khôi phục bản rõ.

paddown
Kẻ tấn công sửa một byte trong block trước rồi gửi ciphertext đã modifie đến server; khi server trả padding k hợp lệ, tiếp tục thử các giá trị khác, đến khi phản hồi padding hợp lệ tức là giá trị thử đã đúng byte, từ đó suy ra intermediate value I[j] (I = D_k(C_i)); cuối cùng tính plaintext byte gốc bằng công thức P_i[j] = I[j] XOR C_{i-1}[j] (với C_{i-1} là block trước bản gốc).
Cứ như thế, dựa vào phản hồi padding hợp lệ hay k để tìm ra được thông tin gốc

Trong file paddown attack, Script sẽ tự động gửi các ciphertext thay đổi từng byte, phân tích phản hồi để tìm byte đúng.
Kết quả cuối cùng thu được là bản rõ ‘This is a padded plaintext’ – chứng minh tấn công thành công.”
