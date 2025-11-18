from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class InvalidPadding(BaseException):
    pass

class VulnerableEncryptionService:

    key = b"deadbeeffeedface"  # Secret key, only known to service
    iv = b"FEDCBA9876543210"  # Public IV, usually prepended to ciphertext

    def encrypt(self, plaintext):
        
        cipher = AES.new(self.key, AES.MODE_CBC, IV=self.iv)
        return self.iv + cipher.encrypt(pad(plaintext, 16))

    def decrypt(self, ciphertext):
        
        cipher = AES.new(self.key, AES.MODE_CBC, IV=self.iv)
        try:
            unpad(cipher.decrypt(ciphertext), 16)
        except ValueError:
            raise InvalidPadding("Invalid PKCS7 Padding")
        return "Decryption successful!"
