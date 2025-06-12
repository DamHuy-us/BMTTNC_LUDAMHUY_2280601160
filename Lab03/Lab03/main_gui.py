# main_gui.py
import sys
import requests # Thư viện để gửi HTTP requests
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import QMessageBox # Để hiển thị thông báo lỗi/thành công

# Import lớp Ui_Dialog từ file rsa.py đã được generate
# Đảm bảo đường dẫn này đúng với vị trí của file rsa.py
from ui.rsa import Ui_Dialog

# URL cơ sở của Flask API của bạn
BASE_API_URL = "http://127.0.0.1:5000/api/rsa" # Hoặc địa chỉ IP/port của server Flask của bạn

class RSAGui(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.setWindowTitle("RSA Cipher Application") # Đặt lại tiêu đề cửa sổ

        # Kết nối các nút bấm với các hàm xử lý
        self.ui.pushButton.clicked.connect(self.encrypt_message)       # Encrypt
        self.ui.pushButton_2.clicked.connect(self.decrypt_message)      # Decrypt
        self.ui.pushButton_3.clicked.connect(self.sign_message)         # Sign
        self.ui.pushButton_4.clicked.connect(self.verify_signature)     # Verify
        self.ui.pushButton_5.clicked.connect(self.generate_keys)        # Generate Keys (Lưu ý: nút này có typo là "generste keys\" trong UI, nên sửa lại trong Qt Designer nếu có thể)

        # Cập nhật label "information" để người dùng biết đã tạo khóa hay chưa
        self.ui.textEdit_4.setReadOnly(True) # Đặt textEdit_4 (Information) chỉ đọc
        self.update_information_display("Chưa tạo khóa. Vui lòng nhấn 'Generate Keys'.")


    def update_information_display(self, message, is_error=False):
        """Cập nhật nội dung cho textEdit_4 (Information)"""
        self.ui.textEdit_4.setText(message)
        if is_error:
            self.ui.textEdit_4.setStyleSheet("color: red;")
        else:
            self.ui.textEdit_4.setStyleSheet("color: black;") # Đặt lại màu chữ bình thường


    def show_message_box(self, title, message, icon=QMessageBox.Information):
        """Hàm trợ giúp để hiển thị hộp thoại thông báo."""
        msg_box = QMessageBox()
        msg_box.setIcon(icon)
        msg_box.setText(message)
        msg_box.setWindowTitle(title)
        msg_box.setStandardButtons(QMessageBox.Ok)
        msg_box.exec_()

    # --- Các hàm gọi API Flask ---

    def generate_keys(self):
        self.update_information_display("Đang tạo khóa...")
        try:
            response = requests.get(f"{BASE_API_URL}/generate_keys")
            response.raise_for_status() # Ném lỗi HTTP nếu status code là 4xx hoặc 5xx
            data = response.json()
            self.show_message_box("Thành công", data.get("message", "Đã tạo khóa thành công!"))
            self.update_information_display("Đã tạo cặp khóa RSA mới.")
        except requests.exceptions.ConnectionError:
            self.show_message_box("Lỗi kết nối", "Không thể kết nối đến server Flask. Đảm bảo server đang chạy.", QMessageBox.Critical)
            self.update_information_display("Lỗi: Không thể kết nối server.", is_error=True)
        except requests.exceptions.HTTPError as e:
            error_data = e.response.json() if e.response.content else {"error": str(e)}
            self.show_message_box("Lỗi API", f"Lỗi khi tạo khóa: {error_data.get('error', 'Không xác định')}", QMessageBox.Warning)
            self.update_information_display(f"Lỗi tạo khóa: {error_data.get('error', 'Không xác định')}", is_error=True)
        except Exception as e:
            self.show_message_box("Lỗi", f"Đã xảy ra lỗi không mong muốn: {e}", QMessageBox.Critical)
            self.update_information_display(f"Lỗi không mong muốn: {e}", is_error=True)


    def encrypt_message(self):
        plaintext = self.ui.textEdit_2.toPlainText() # Lấy nội dung từ ô plaintext
        if not plaintext:
            self.show_message_box("Lỗi", "Vui lòng nhập tin nhắn cần mã hóa (plaintext).", QMessageBox.Warning)
            return

        self.update_information_display("Đang mã hóa...")
        try:
            # Gửi yêu cầu POST với dữ liệu JSON
            payload = {
                "message": plaintext,
                "key_type": "public" # Mã hóa bằng khóa công khai
            }
            response = requests.post(f"{BASE_API_URL}/encrypt", json=payload)
            response.raise_for_status()
            data = response.json()
            encrypted_message = data.get("encrypted_message", "")
            self.ui.textEdit.setText(encrypted_message) # Hiển thị ciphertext
            self.show_message_box("Thành công", "Tin nhắn đã được mã hóa.")
            self.update_information_display("Đã mã hóa tin nhắn thành công.")
        except requests.exceptions.ConnectionError:
            self.show_message_box("Lỗi kết nối", "Không thể kết nối đến server Flask. Đảm bảo server đang chạy.", QMessageBox.Critical)
            self.update_information_display("Lỗi: Không thể kết nối server.", is_error=True)
        except requests.exceptions.HTTPError as e:
            error_data = e.response.json() if e.response.content else {"error": str(e)}
            self.show_message_box("Lỗi API", f"Lỗi khi mã hóa: {error_data.get('error', 'Không xác định')}", QMessageBox.Warning)
            self.update_information_display(f"Lỗi mã hóa: {error_data.get('error', 'Không xác định')}", is_error=True)
        except Exception as e:
            self.show_message_box("Lỗi", f"Đã xảy ra lỗi không mong muốn: {e}", QMessageBox.Critical)
            self.update_information_display(f"Lỗi không mong muốn: {e}", is_error=True)


    def decrypt_message(self):
        ciphertext_hex = self.ui.textEdit.toPlainText() # Lấy nội dung từ ô ciphertext
        if not ciphertext_hex:
            self.show_message_box("Lỗi", "Vui lòng nhập ciphertext cần giải mã.", QMessageBox.Warning)
            return

        self.update_information_display("Đang giải mã...")
        try:
            payload = {
                "ciphertext": ciphertext_hex,
                "key_type": "private" # Giải mã bằng khóa riêng tư
            }
            response = requests.post(f"{BASE_API_URL}/decrypt", json=payload)
            response.raise_for_status()
            data = response.json()
            decrypted_message = data.get("decrypted_message", "")
            # Giả định có một textEdit khác để hiển thị decrypted_message nếu muốn
            # Hiện tại, UI của bạn có textEdit_2 là plaintext, textEdit là ciphertext.
            # Bạn có thể hiển thị decrypted_message trở lại textEdit_2 hoặc tạo một textEdit mới.
            self.ui.textEdit_2.setText(decrypted_message) # Hiển thị lại plaintext vào ô cũ
            self.show_message_box("Thành công", "Tin nhắn đã được giải mã.")
            self.update_information_display("Đã giải mã tin nhắn thành công.")
        except requests.exceptions.ConnectionError:
            self.show_message_box("Lỗi kết nối", "Không thể kết nối đến server Flask. Đảm bảo server đang chạy.", QMessageBox.Critical)
            self.update_information_display("Lỗi: Không thể kết nối server.", is_error=True)
        except requests.exceptions.HTTPError as e:
            error_data = e.response.json() if e.response.content else {"error": str(e)}
            self.show_message_box("Lỗi API", f"Lỗi khi giải mã: {error_data.get('error', 'Không xác định')}", QMessageBox.Warning)
            self.update_information_display(f"Lỗi giải mã: {error_data.get('error', 'Không xác định')}", is_error=True)
        except Exception as e:
            self.show_message_box("Lỗi", f"Đã xảy ra lỗi không mong muốn: {e}", QMessageBox.Critical)
            self.update_information_display(f"Lỗi không mong muốn: {e}", is_error=True)

    def sign_message(self):
        message_to_sign = self.ui.textEdit_2.toPlainText() # Lấy tin nhắn từ ô plaintext để ký
        if not message_to_sign:
            self.show_message_box("Lỗi", "Vui lòng nhập tin nhắn cần ký.", QMessageBox.Warning)
            return

        self.update_information_display("Đang ký tin nhắn...")
        try:
            payload = {
                "message": message_to_sign
            }
            response = requests.post(f"{BASE_API_URL}/sign", json=payload)
            response.raise_for_status()
            data = response.json()
            signature = data.get("signature", "")
            self.ui.textEdit_3.setText(signature) # Hiển thị chữ ký vào ô signature
            self.show_message_box("Thành công", "Tin nhắn đã được ký.")
            self.update_information_display("Đã ký tin nhắn thành công.")
        except requests.exceptions.ConnectionError:
            self.show_message_box("Lỗi kết nối", "Không thể kết nối đến server Flask. Đảm bảo server đang chạy.", QMessageBox.Critical)
            self.update_information_display("Lỗi: Không thể kết nối server.", is_error=True)
        except requests.exceptions.HTTPError as e:
            error_data = e.response.json() if e.response.content else {"error": str(e)}
            self.show_message_box("Lỗi API", f"Lỗi khi ký: {error_data.get('error', 'Không xác định')}", QMessageBox.Warning)
            self.update_information_display(f"Lỗi ký: {error_data.get('error', 'Không xác định')}", is_error=True)
        except Exception as e:
            self.show_message_box("Lỗi", f"Đã xảy ra lỗi không mong muốn: {e}", QMessageBox.Critical)
            self.update_information_display(f"Lỗi không mong muốn: {e}", is_error=True)


    def verify_signature(self):
        original_message = self.ui.textEdit_2.toPlainText() # Lấy tin nhắn gốc từ ô plaintext
        signature_hex = self.ui.textEdit_3.toPlainText()     # Lấy chữ ký từ ô signature

        if not original_message or not signature_hex:
            self.show_message_box("Lỗi", "Vui lòng nhập tin nhắn gốc và chữ ký để xác minh.", QMessageBox.Warning)
            return

        self.update_information_display("Đang xác minh chữ ký...")
        try:
            payload = {
                "message": original_message,
                "signature": signature_hex
            }
            response = requests.post(f"{BASE_API_URL}/verify", json=payload)
            response.raise_for_status()
            data = response.json()
            is_verified = data.get("is_verified", False)
            
            if is_verified:
                self.show_message_box("Xác minh thành công", "Chữ ký hợp lệ!", QMessageBox.Information)
                self.update_information_display("Xác minh chữ ký: Hợp lệ.")
            else:
                self.show_message_box("Xác minh thất bại", "Chữ ký KHÔNG hợp lệ hoặc không khớp với tin nhắn.", QMessageBox.Warning)
                self.update_information_display("Xác minh chữ ký: KHÔNG hợp lệ.", is_error=True)

        except requests.exceptions.ConnectionError:
            self.show_message_box("Lỗi kết nối", "Không thể kết nối đến server Flask. Đảm bảo server đang chạy.", QMessageBox.Critical)
            self.update_information_display("Lỗi: Không thể kết nối server.", is_error=True)
        except requests.exceptions.HTTPError as e:
            error_data = e.response.json() if e.response.content else {"error": str(e)}
            self.show_message_box("Lỗi API", f"Lỗi khi xác minh: {error_data.get('error', 'Không xác định')}", QMessageBox.Warning)
            self.update_information_display(f"Lỗi xác minh: {error_data.get('error', 'Không xác định')}", is_error=True)
        except Exception as e:
            self.show_message_box("Lỗi", f"Đã xảy ra lỗi không mong muốn: {e}", QMessageBox.Critical)
            self.update_information_display(f"Lỗi không mong muốn: {e}", is_error=True)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = RSAGui()
    window.show()
    sys.exit(app.exec_())