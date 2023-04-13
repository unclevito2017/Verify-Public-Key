from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from binascii import unhexlify

# Prompt the user for the public key
public_key_hex = input('Enter public key in hex format: ')

# Convert the public key from hex to bytes
public_key_bytes = unhexlify(public_key_hex)

# Extract the x-coordinate and y-coordinate from the bytes
if public_key_bytes[0] == 0x04:  # uncompressed public key
    x = int.from_bytes(public_key_bytes[1:33], 'big')
    y = int.from_bytes(public_key_bytes[33:], 'big')
elif public_key_bytes[0] in [0x02, 0x03]:  # compressed public key
    x = int.from_bytes(public_key_bytes[1:], 'big')
    y_squared = (x ** 3 + secp256k1.a * x + secp256k1.b) % secp256k1.p
    y = pow(y_squared, (secp256k1.p + 1) // 4, secp256k1.p)
    if public_key_bytes[0] == 0x03:
        y = secp256k1.p - y
else:
    raise ValueError('Invalid public key format')

# Create a point object
public_key_point = Point(x, y, curve=secp256k1)

# Check if the point is on the curve
if secp256k1.is_point_on_curve((public_key_point.x, public_key_point.y)):
    print('Point is on curve')
else:
    print('Point is not on curve')
