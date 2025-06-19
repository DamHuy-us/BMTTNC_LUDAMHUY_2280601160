# encrypt.py
import sys
from PIL import Image

def encode_image(image_path, message):
    img = Image.open(image_path)
    width, height = img.size
    # pixel_index = 0  # Biến này không được sử dụng, có thể bỏ qua
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    binary_message += '1111111111111110' # Đánh dấu kết thúc thông điệp (16 bit)

    data_index = 0
    for row in range(height):
        for col in range(width):
            pixel = list(img.getpixel((col, row))) # Chú ý: getpixel trả về tuple, cần chuyển sang list để chỉnh sửa

            for color_channel in range(3): # Duyệt qua R, G, B
                if data_index < len(binary_message):
                    # Thay đổi LSB của kênh màu
                    original_channel_binary = format(pixel[color_channel], '08b')
                    modified_channel_binary = original_channel_binary[:-1] + binary_message[data_index]
                    pixel[color_channel] = int(modified_channel_binary, 2)
                    data_index += 1

            # Sửa lỗi TypeError: putpixel nhận 2 đối số: tọa độ và giá trị màu
            img.putpixel((col, row), tuple(pixel))

            if data_index >= len(binary_message):
                break
        if data_index >= len(binary_message):
            break

    encoded_image_path = 'encoded_image.png'
    img.save(encoded_image_path)
    print("Steganography complete. Encoded image saved as", encoded_image_path)

def main():
    if len(sys.argv) != 3:
        print("Usage: python encrypt.py <image_path> <message>")
        return

    image_path = sys.argv[1]
    message = sys.argv[2]
    encode_image(image_path, message)

if __name__ == "__main__":
    main()