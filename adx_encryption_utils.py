'''
Created on 18/06/2014

@author: pablin
'''
import base64
import hmac
import hashlib
import realtime_bidding_pb2 as rtb_pb2

class AdxEncryptionException(Exception): pass

def int2bytes(i, padding=4):
    h = hex(i)
    bytes4 = hex2bytes(h)
    while len(bytes4) < padding:
        bytes4 = chr(0) + bytes4
    return bytes4

def hex2bytes(h):
    if len(h) > 1 and h[0:2] == '0x':
        h = h[2:]
    if len(h) % 2:
        h = "0" + h
    return h.decode('hex')

def add_base64_padding(nopadding):
    nopadding += "=" * ((4 - len(nopadding) % 4) % 4)
    return nopadding

def my_hmac(key, body):
    return hmac.new(key, body, hashlib.sha1).digest()

def get_iv_cipher_signature(byte_str):
    iv = byte_str[:16]
    signature = byte_str[-4:]
    price = byte_str[16:-4]
    return (iv, price, signature)

def xor_strings(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

def adx_unencrypt(byte_str, enc_key, int_key = None):
    iv, ciphertext, signature = get_iv_cipher_signature(byte_str)
    price_pad = my_hmac(enc_key, iv)
    hex_text = xor_strings( price_pad, ciphertext)
    plaint_text = hex_text
    
    # Check signature
    if int_key != None :
        confirm_sig = my_hmac(int_key, hex_text + iv)
        confirm_sig = confirm_sig[:4] # only the first 4 bytes
        if ( signature != confirm_sig):
            raise AdxEncryptionException("Invalid signature (%s != %s)" % 
                                         (signature, confirm_sig))
        
    return plaint_text


def adx_unencrypt_price(b64_str, enc_key, int_key = None):
    #TODO check network byte order
    # Base 64 --> bytes
    b64_str = add_base64_padding(b64_str)
    byte_array = base64.urlsafe_b64decode(b64_str)
    hex_text = adx_unencrypt(byte_array, enc_key, int_key)
    return int(hex_text.encode('hex'), 16)

def adx_encrypt_price(price, enc_key, int_key, iv):
    #TODO check network byte order
    if len(iv) != 16:
        raise AdxEncryptionException("IV is not 16 bytes long")
    int_8bytes = int2bytes(price, 8)
    pad = my_hmac(enc_key, iv)[:8]
    enc_price = xor_strings(pad, int_8bytes)
    signature = my_hmac(int_key, int_8bytes + iv)[:4]
    return base64.urlsafe_b64encode( iv + enc_price + signature )

def chunks(l, n): 
    return [l[x: x+n] for x in xrange(0, len(l), n)]

def adx_decrypt(enc_bytes, enc_key, int_key = None):
    iv, cipher, sig = get_iv_cipher_signature(enc_bytes)
    
    cipher_chunks = chunks(cipher, 20)
    byte_array = ""
    for i in range(len(cipher_chunks)):
        if i == 0:
            pad = my_hmac(enc_key, iv)
        else : 
            pad = my_hmac(enc_key, iv + chr(i-1))
        unenc_bytes = xor_strings(cipher_chunks[i], pad)
        byte_array = byte_array + unenc_bytes
        
    if ( int_key is not None):
        signature = my_hmac(int_key, byte_array + iv)[:4]
        if ( signature != sig):
            raise AdxEncryptionException("Invalid signature (%s != %s)" % 
                                         (signature, sig))
    return byte_array

def adx_encrypt(byte_array, enc_key, int_key, iv):
    
    sections = chunks(byte_array, 20)
    enc_sections = ""
    for i in range(len(sections)):
        if i == 0:
            pad = my_hmac(enc_key, iv)
        else :
            pad = my_hmac(enc_key, iv + chr(i-1))
        enc_section = xor_strings(sections[i], pad)
        enc_sections = enc_sections + enc_section
    
    signature = my_hmac(int_key, byte_array + iv)[:4]
    final_msg = iv + enc_sections + signature
    
    return final_msg

def decrypt_hyperlocalset(hyperlocalset, enc_key, int_key):
    dec_hyp = adx_decrypt(hyperlocalset, enc_key, int_key)
    hpls = rtb_pb2.BidRequest.HyperlocalSet()
    hpls.ParseFromString(dec_hyp)
    return hpls

def encrypt_hyperlocalset(hyperlocalset, enc_key, int_key, iv):
    bts = hyperlocalset.SerializePartialToString()
    enc_hyp = adx_encrypt(bts, enc_key, int_key, iv)
    return enc_hyp

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']

    enc_key = [ 0xb0, 0x8c, 0x70, 0xcf, 0xbc, 0xb0, 0xeb, 0x6c, 0xab, 0x7e, 0x82, 0xc6,
      0xb7, 0x5d, 0xa5, 0x20, 0x72, 0xae, 0x62, 0xb2, 0xbf, 0x4b, 0x99, 0x0b,
      0xb8, 0x0a, 0x48, 0xd8, 0x14, 0x1e, 0xec, 0x07 ]
    enc_key = ''.join(chr(x) for x in enc_key)
    
    int_key = [ 0xbf, 0x77, 0xec, 0x55, 0xc3, 0x01, 0x30, 0xc1, 0xd8, 0xcd, 0x18, 0x62,
      0xed, 0x2a, 0x4c, 0xd2, 0xc7, 0x6a, 0xc3, 0x3b, 0xc0, 0xc4, 0xce, 0x8a,
      0x3d, 0x3b, 0xbd, 0x3a, 0xd5, 0x68, 0x77, 0x92 ]
    int_key = ''.join(chr(x) for x in int_key)
    
    enc_price = "SjpvRwAB4kB7jEpgW5IA8p73ew9ic6VZpFsPnA"
    bts = adx_unencrypt_price(enc_price, enc_key, int_key)
    
    print "Enc key :"
    print enc_key.encode("hex")
    print "Int Key :"
    print int_key
    print int_key.encode("hex")
    print int_key.encode("hex").decode("hex")
    print "price decoded: %d" % bts
    
    
    