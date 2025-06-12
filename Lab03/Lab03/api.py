from flask import Flask, request, jsonify
from cipher.rsa.rsa_cipher import RSACipher
import logging

# Cấu hình logging
# Nên dùng logger của Flask thay vì logger gốc, hoặc ít nhất là cấu hình mạnh mẽ hơn
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# RSA CIPHER ALGORITHM
rsa_cipher = RSACipher()

@app.route('/api/rsa/generate_keys', methods=['GET'])
def rsa_generate_keys():
    try:
        rsa_cipher.generate_keys()
        return jsonify({'message': 'Keys generated successfully'}), 200 # Thêm mã trạng thái 200 OK
    except Exception as e:
        logger.error(f"Lỗi khi tạo khóa: {e}")
        return jsonify({'error': f'Failed to generate keys: {str(e)}'}), 500

@app.route("/api/rsa/encrypt", methods=["POST"])
def rsa_encrypt():
    try:
        # Flask tự động xử lý lỗi 400 Bad Request nếu request.get_json() không thành công
        # do Content-Type sai hoặc JSON không hợp lệ.
        # Bạn không cần thêm khối try-except bọc quanh request.get_json() nữa.
        # Nếu muốn bắt lỗi JSON cụ thể hơn, bạn có thể thêm ImportError hoặc ValueError
        data = request.get_json()

        if not data:
            return jsonify({'error': 'Request body must be valid JSON'}), 400
        if 'message' not in data or 'key_type' not in data:
            return jsonify({'error': 'Missing "message" or "key_type" in request body'}), 400

        message = data['message']
        key_type = data['key_type']

        # Đảm bảo khóa đã được tạo trước khi tải
        try:
            private_key, public_key = rsa_cipher.load_keys()
        except FileNotFoundError:
            return jsonify({'error': 'RSA keys not found. Please generate keys first by calling /api/rsa/generate_keys.'}), 404
        except Exception as e:
            logger.error(f"Lỗi khi tải khóa: {e}")
            return jsonify({'error': f'Failed to load keys: {str(e)}'}), 500


        if key_type == 'public':
            key = public_key
        elif key_type == 'private':
            return jsonify({'error': 'Encryption with private key is not supported by standard RSA encryption. Use public key for encryption.'}), 400
        else:
            return jsonify({'error': 'Invalid key type. Must be "public".'}), 400

        encrypted_message = rsa_cipher.encrypt(message, key)
        encrypted_hex = encrypted_message.hex()
        return jsonify({'encrypted_message': encrypted_hex}), 200 # Thêm mã trạng thái 200 OK

    except Exception as e:
        logger.error(f"Lỗi chung khi mã hóa: {e}")
        # Lỗi 400 Bad Request do JSON parsing đã được Flask xử lý mặc định.
        # Các lỗi khác (ví dụ: lỗi từ rsa_cipher.encrypt) sẽ được bắt ở đây.
        return jsonify({'error': f'Encryption failed: {str(e)}'}), 500

@app.route("/api/rsa/decrypt", methods=["POST"])
def rsa_decrypt():
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'Request body must be valid JSON'}), 400
        if 'ciphertext' not in data or 'key_type' not in data:
            return jsonify({'error': 'Missing "ciphertext" or "key_type" in request body'}), 400

        ciphertext_hex = data['ciphertext']
        key_type = data['key_type']

        # Đảm bảo khóa đã được tạo trước khi tải
        try:
            private_key, public_key = rsa_cipher.load_keys()
        except FileNotFoundError:
            return jsonify({'error': 'RSA keys not found. Please generate keys first by calling /api/rsa/generate_keys.'}), 404
        except Exception as e:
            logger.error(f"Lỗi khi tải khóa: {e}")
            return jsonify({'error': f'Failed to load keys: {str(e)}'}), 500

        if key_type == 'private':
            key = private_key
        elif key_type == 'public':
            return jsonify({'error': 'Decryption with public key is not supported by standard RSA decryption. Use private key for decryption.'}), 400
        else:
            return jsonify({'error': 'Invalid key type. Must be "private".'}), 400

        try:
            ciphertext = bytes.fromhex(ciphertext_hex)
        except ValueError:
            return jsonify({'error': 'Invalid ciphertext format. Ciphertext must be a valid hexadecimal string.'}), 400

        decrypted_message = rsa_cipher.decrypt(ciphertext, key)

        if decrypted_message is False:
            # Lỗi giải mã do key sai hoặc ciphertext không đúng
            return jsonify({'error': 'Decryption failed. This might be due to an incorrect key or corrupted ciphertext.'}), 400

        return jsonify({'decrypted_message': decrypted_message}), 200 # Thêm mã trạng thái 200 OK

    except Exception as e:
        logger.error(f"Lỗi chung khi giải mã: {e}")
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 500

@app.route('/api/rsa/sign', methods=['POST'])
def rsa_sign_message():
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'Request body must be valid JSON'}), 400
        if 'message' not in data:
            return jsonify({'error': 'Missing "message" in request body'}), 400

        message = data['message']
        
        # Đảm bảo khóa đã được tạo trước khi tải
        try:
            private_key, _ = rsa_cipher.load_keys()
        except FileNotFoundError:
            return jsonify({'error': 'RSA keys not found. Please generate keys first by calling /api/rsa/generate_keys.'}), 404
        except Exception as e:
            logger.error(f"Lỗi khi tải khóa: {e}")
            return jsonify({'error': f'Failed to load keys: {str(e)}'}), 500

        signature = rsa_cipher.sign(message, private_key)
        signature_hex = signature.hex()

        return jsonify({'signature': signature_hex}), 200 # Thêm mã trạng thái 200 OK
    except Exception as e:
        logger.error(f"Lỗi chung khi ký: {e}")
        return jsonify({'error': f'Signing failed: {str(e)}'}), 500

@app.route('/api/rsa/verify', methods=['POST'])
def rsa_verify_signature():
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'Request body must be valid JSON'}), 400
        if 'message' not in data or 'signature' not in data:
            return jsonify({'error': 'Missing "message" or "signature" in request body'}), 400

        message = data['message']
        signature_hex = data['signature']
        
        # Đảm bảo khóa đã được tạo trước khi tải
        try:
            _, public_key = rsa_cipher.load_keys()
        except FileNotFoundError:
            return jsonify({'error': 'RSA keys not found. Please generate keys first by calling /api/rsa/generate_keys.'}), 404
        except Exception as e:
            logger.error(f"Lỗi khi tải khóa: {e}")
            return jsonify({'error': f'Failed to load keys: {str(e)}'}), 500

        try:
            signature = bytes.fromhex(signature_hex)
        except ValueError:
            return jsonify({'error': 'Invalid signature format. Signature must be a valid hexadecimal string.'}), 400

        is_verified = rsa_cipher.verify(message, signature, public_key)

        # Điều chỉnh thông báo trả về cho rõ ràng hơn
        if is_verified:
            return jsonify({'is_verified': True, 'message': 'Signature is valid.'}), 200
        else:
            return jsonify({'is_verified': False, 'message': 'Signature is NOT valid or does not match the message.'}), 200 # Vẫn 200 OK vì verification là thành công, chỉ kết quả là False

    except Exception as e:
        logger.error(f"Lỗi chung khi xác minh: {e}")
        return jsonify({'error': f'Verification failed: {str(e)}'}), 500

# Main function
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)