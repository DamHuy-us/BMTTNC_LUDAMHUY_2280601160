import rsa
import os
import logging

# Cấu hình logging để ghi lỗi (cố định định dạng nếu muốn nhất quán)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

KEYS_DIR = os.path.join(os.path.dirname(__file__), 'keys') # Sử dụng os.path.join và dirname để đảm bảo đường dẫn tương đối đúng
                                                          # và không bị lỗi trên các hệ điều hành khác nhau
if not os.path.exists(KEYS_DIR):
    try:
        os.makedirs(KEYS_DIR)
        logger.info(f"Đã tạo thư mục lưu khóa: {KEYS_DIR}")
    except OSError as e:
        logger.critical(f"Không thể tạo thư mục {KEYS_DIR}. Vui lòng kiểm tra quyền truy cập hoặc cấu trúc thư mục: {e}")
        raise # Ném ngoại lệ để dừng ứng dụng nếu không thể tạo thư mục khóa

class RSACipher:
    def __init__(self):
        pass

    def generate_keys(self, key_size=2048):
        """
        Tạo cặp khóa RSA mới (khóa công khai và khóa riêng tư)
        và lưu chúng vào các file .pem.
        Tham số:
            key_size (int): Kích thước khóa (mặc định 2048-bit).
        """
        try:
            (public_key, private_key) = rsa.newkeys(key_size)
            with open(os.path.join(KEYS_DIR, 'publicKey.pem'), 'wb') as p:
                p.write(public_key.save_pkcs1('PEM'))
            with open(os.path.join(KEYS_DIR, 'privateKey.pem'), 'wb') as p:
                p.write(private_key.save_pkcs1('PEM'))
            logger.info("Tạo và lưu cặp khóa RSA thành công.")
        except Exception as e:
            logger.error(f"Lỗi khi tạo khóa RSA: {e}")
            raise # Ném lại ngoại lệ để Flask API có thể bắt và trả về lỗi 500

    def load_keys(self):
        """
        Tải cặp khóa RSA từ các file .pem.
        Trả về: private_key, public_key
        """
        try:
            # Kiểm tra xem file có tồn tại không trước khi mở
            public_key_path = os.path.join(KEYS_DIR, 'publicKey.pem')
            private_key_path = os.path.join(KEYS_DIR, 'privateKey.pem')

            if not os.path.exists(public_key_path) or not os.path.exists(private_key_path):
                raise FileNotFoundError(f"Missing one or both key files in {KEYS_DIR}")

            with open(public_key_path, 'rb') as p:
                public_key = rsa.PublicKey.load_pkcs1(p.read())
            with open(private_key_path, 'rb') as p:
                private_key = rsa.PrivateKey.load_pkcs1(p.read())
            return private_key, public_key
        except FileNotFoundError as e:
            logger.warning(f"Không tìm thấy file khóa: {e}. Vui lòng tạo khóa trước.")
            raise # Quan trọng: Ném ngoại lệ để Flask API có thể trả về lỗi 404 cho client
        except Exception as e:
            logger.error(f"Lỗi khi tải khóa RSA: {e}")
            raise # Ném lại ngoại lệ để Flask API có thể bắt và trả về lỗi 500

    def encrypt(self, message, key):
        """
        Mã hóa một tin nhắn bằng khóa RSA đã cho.
        Tham số:
            message (str): Tin nhắn cần mã hóa.
            key (rsa.PublicKey): Khóa công khai để mã hóa.
        Trả về: bytes: Tin nhắn đã mã hóa.
        """
        try:
         
            return rsa.encrypt(message.encode('utf-8'), key)
        except rsa.pkcs1.CryptoError as e: # Bắt lỗi cụ thể hơn của thư viện rsa
            logger.error(f"Lỗi mã hóa RSA (kích thước tin nhắn quá lớn?): {e}")
            raise ValueError(f"Encryption error: {e}. Message might be too long for direct RSA encryption.")
        except UnicodeEncodeError as e:
            logger.error(f"Lỗi mã hóa tin nhắn, kiểm tra định dạng chuỗi (không thể encode utf-8): {e}")
            raise ValueError(f"Encoding error: {e}")
        except Exception as e:
            logger.error(f"Lỗi không xác định khi mã hóa: {e}")
            raise ValueError(f"Unknown encryption error: {e}")

    def decrypt(self, ciphertext, key):
        """
        Giải mã một tin nhắn đã mã hóa bằng khóa RSA đã cho.
        Tham số:
            ciphertext (bytes): Tin nhắn đã mã hóa.
            key (rsa.PrivateKey): Khóa riêng tư để giải mã.
        Trả về: str: Tin nhắn đã giải mã.
        """
        try:
            # rsa.decrypt cũng có thể cần xử lý khối nếu tin nhắn gốc lớn
            return rsa.decrypt(ciphertext, key).decode('utf-8')
        except rsa.pkcs1.DecryptionError as e: # Bắt lỗi giải mã cụ thể
            logger.error(f"Lỗi giải mã (khóa sai hoặc ciphertext không hợp lệ): {e}")
            return False # Trả về False như bạn đã định nghĩa
        except Exception as e:
            logger.error(f"Lỗi không xác định khi giải mã: {e}")
            return False # Trả về False

    def sign(self, message, key):
        """
        Ký một tin nhắn bằng khóa riêng tư.
        Tham số:
            message (str): Tin nhắn cần ký.
            key (rsa.PrivateKey): Khóa riêng tư để ký.
        Trả về: bytes: Chữ ký số.
        """
        try:
           
            return rsa.sign(message.encode('utf-8'), key, 'SHA-256')
        except Exception as e:
            logger.error(f"Lỗi khi ký tin nhắn: {e}")
            raise ValueError(f"Signing error: {e}") # Ném lỗi cụ thể hơn

    def verify(self, message, signature, key):
        """
        Xác minh chữ ký số của một tin nhắn bằng khóa công khai.
        Tham số:
            message (str): Tin nhắn gốc.
            signature (bytes): Chữ ký số cần xác minh.
            key (rsa.PublicKey): Khóa công khai để xác minh.
        Trả về: bool: True nếu chữ ký hợp lệ, False nếu không.
        """
        try:
            # rsa.verify sẽ ném lỗi nếu chữ ký không hợp lệ, không phải trả về False
            # Nên cần bắt ngoại lệ để trả về False.
            rsa.verify(message.encode('utf-8'), signature, key)
            return True # Nếu không có lỗi, chữ ký hợp lệ
        except rsa.pkcs1.VerificationError: # Bắt lỗi xác minh cụ thể
            logger.warning("Chữ ký không hợp lệ hoặc không khớp với tin nhắn.")
            return False
        except Exception as e:
            logger.error(f"Lỗi không xác định khi xác minh chữ ký: {e}")
            return False