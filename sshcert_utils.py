from struct import pack, unpack
from secrets import randbits

# Generates a nonce from the secrets module
# Generally more secure than the random library
def generate_secure_nonce(bits: int) -> str:
    return str(randbits(bits))

def encode_string(source_string, encoding: str = 'utf-8') -> bytes:
    if isinstance(source_string, str):
        source_string = source_string.encode(encoding)
        
    if isinstance(source_string, bytes):
        return pack('>I', len(source_string)) + source_string
    else:
        raise TypeError("Expected unicode or bytes, got {!r}. Try specifying a different encoding.".format(source_string))

def encode_boolean(source_bool: bool) -> bytes:
    return pack("B", 1) if source_bool else pack("B", 0)

def encode_int(source_int: int) -> bytes:
    return pack('>I', source_int)

def encode_int64(source_int: int) -> bytes:
    return pack('>Q', source_int)

def encode_mpint(source_int: int) -> bytes:
    if source_int < 0:
        raise ValueError("MPInts must be positive")
    
    length = source_int.bit_length() // 8 + 1
    return encode_string(source_int.to_bytes(length, 'big'))

def encode_list(source_list: list, null_separator: bool = False):
    if null_separator:
        return encode_string(encode_string('').join([
            encode_string(x) for x in source_list
        ]) + encode_string(''))
    else:
        return encode_string(b''.join([encode_string(x) for x in source_list]))

def encode_rsa_signature(sig: bytes, type: bytes) -> bytes:
    return encode_string(encode_string(type) + encode_string(sig))

def encode_dsa_signature(sig_r: bytes, sig_s: bytes, curve: str):
    signature = encode_mpint(sig_r) + encode_mpint(sig_s)
    return encode_string(encode_string(curve) + encode_string(signature))

def decode_string(data: bytes) -> tuple:
    size = unpack('>I', data[:4])[0]+4
    return data[4:size], data[size:]

def decode_int(data: bytes) -> tuple:
    return int(unpack('>I', data[:4])[0]), data[4:]

def decode_int64(data: bytes) -> tuple:
    return int(unpack('>Q', data[:8])[0]), data[8:]

def decode_mpint(data: bytes) -> tuple:
    mpint_str, data = decode_string(data)
    return int.from_bytes(mpint_str, 'big'), data

def decode_list(data: bytes, null_separator: bool = False) -> tuple:
    layer_one, data = decode_string(data)
        
    lst = []
    while len(layer_one) > 0:
        elem, layer_one = decode_string(layer_one)
        if not null_separator:
            lst.append(elem)
        else:
            lst.append(elem) if elem != b'' else None
        
    return lst, data

def decode_dsa_signature(data: bytes) -> tuple:
    signature = {}
    layer_one, data = decode_string(data)
    
    signature['curve'], layer_one = decode_string(layer_one)
    encoded_sig, layer_one = decode_string(layer_one)
    signature['r'], encoded_sig = decode_mpint(encoded_sig)
    signature['s'] = decode_mpint(encoded_sig)[0]
    
    return signature, data

def decode_rsa_signature(data: bytes) -> tuple:
    signature = {}
    layer_one, data = decode_string(data)
    
    signature['type'], layer_one = decode_string(layer_one)
    signature['data'] = decode_string(layer_one)[0]
    
    return signature, data