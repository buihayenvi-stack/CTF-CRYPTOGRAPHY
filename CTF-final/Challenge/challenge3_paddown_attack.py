# Demo Padding Oracle (mô phỏng server dùng IV cố định + trả lỗi rõ ràng)
# - Mục tiêu: minh họa rủi ro khi server **không dùng IV ngẫu nhiên** và
#   trả **thông báo lỗi chi tiết** (ví dụ "Invalid PKCS7 Padding").
# - Kết quả: attacker dùng oracle này để phục hồi **toàn bộ plaintext**.

import sys
import os
from pathlib import Path

# Add parent directory to path to import paddown module
current_dir = Path(__file__).parent
parent_dir = current_dir.parent
sys.path.insert(0, str(parent_dir))

from base64 import b64decode
from vulnerable_encryption_service import InvalidPadding, VulnerableEncryptionService
from paddown import Paddown

if __name__ == "__main__":
    # Ciphertext we would like to decrypt
    ciphertext = b64decode("RkVEQ0JBOTg3NjU0MzIxMIw2tqVlQTrnDQ1wm338Z+ZRWxhz6mVZnv81Ey4MWYTd")

    class MyPaddown(Paddown):
        # Our test padding oracle
        VEC = VulnerableEncryptionService()

        # Implement has_valid_padding to check for padding errors, return False on everything but valid padding.
        def has_valid_padding(self, ciphertext):
            try:
                self.VEC.decrypt(ciphertext)
                return True
            except InvalidPadding:
                return False
            return False

    plaintext_decrypted = MyPaddown(ciphertext).decrypt()
    print(plaintext_decrypted)
