def left_rotate(value, shift):
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF

def md5(message):
    # Initialize Md5 hash variables (A, b, c, d)
    a = 0x67452301
    b = 0xEFCDAB89
    c = 0x98BADCFE
    d = 0x10325476

    # tiền xử lý văn bản
    original_length_bits = len(message) * 8
    message += b'\x80'  # Append a single '1' bit
    
    # chia chuỗi thành độ dài 512 bit (64 byte)
    while len(message) % 64 != 56:
        message += b'\x00'
    
    # Append original length in bits as a 64-bit little-endian integer
    message += original_length_bits.to_bytes(8, 'little')

    # Process message in 512-bit (64-byte) blocks
    for i in range(0, len(message), 64):
        block = message[i : i + 64]
        # divide block into 16 32-bit little-endian words
        words = [int.from_bytes(block[j : j + 4], 'little') for j in range(0, 64, 4)]

        # Save current hash values
        a0, b0, c0, d0 = a, b, c, d

        # Main loop (64 rounds)
        for j in range(64):
            if j < 16:
                f = (b & c) | ((~b) & d)
                g = j
            elif j < 32:
                f = (d & b) | ((~d) & c)
                g = (5 * j + 1) % 16
            elif j < 47:
                f = b ^ c ^ d
                g = (3 * j + 5) % 16
            else:
                f = c ^ (b | (~d))
                g = (7 * j) % 16

            temp = d
            d = c
            c = b
            b = (b + left_rotate((a + f + 0x5A827999 + words[g]) & 0xFFFFFFFF, 3)) & 0xFFFFFFFF
            a = temp
        
        # Add this block's results to the current hash values
        a = (a + a0) & 0xFFFFFFFF
        b = (b + b0) & 0xFFFFFFFF
        c = (c + c0) & 0xFFFFFFFF
        d = (d + d0) & 0xFFFFFFFF

    # Return the final hash as a hexadecimal string
    return '{:08x}{:08x}{:08x}{:08x}'.format(a, b, c, d)

# Get input string from the user
input_string = input("Nhập chuỗi cần băm: ")

# compute the Md5 hash
md5_hash = md5(input_string.encode('utf-8'))

# Print the result
print("Mã băm Md5 của chuỗi '{}' là: {}".format(input_string, md5_hash))
