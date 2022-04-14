#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on 2022/4/13 下午2:12 

@author: dong
"""
from os import urandom

class Hash(object):
    """ Common class for all hash methods.

    It copies the one of the hashlib module (https://docs.python.org/3.5/library/hashlib.html).
    """

    def __init__(self, *args, **kwargs):
        """ Create the Hash object."""
        self.name = self.__class__.__name__  # https://docs.python.org/3.5/library/hashlib.html#hashlib.hash.name
        self.byteorder = 'little'
        self.digest_size = 0  # https://docs.python.org/3.5/library/hashlib.html#hashlib.hash.digest_size
        self.block_size = 0  # https://docs.python.org/3.5/library/hashlib.html#hashlib.hash.block_size

    def __str__(self):
        return self.name

    def update(self, arg):
        """ Update the hash object with the object arg, which must be interpretable as a buffer of bytes."""
        pass

    def digest(self):
        """ Return the digest of the data passed to the update() method so far. This is a bytes object of size digest_size which may contain bytes in the whole range from 0 to 255."""
        return b""

    def hexdigest(self):
        """ Like digest() except the digest is returned as a string object of double length, containing only hexadecimal digits. This may be used to exchange the value safely in email or other non-binary environments."""
        digest = self.digest()
        raw = digest.to_bytes(self.digest_size, byteorder=self.byteorder)
        format_str = '{:0' + str(2 * self.digest_size) + 'x}'
        return format_str.format(int.from_bytes(raw, byteorder='big'))


def leftshift(x, c):
    """ Left shift the number x by c bytes."""
    return x << c
def leftrotate(x, c):
    """ Left rotate the number x by c bytes."""
    x &= 0xFFFFFFFF
    return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

def SHA1_f1(b, c, d):
    """ First ternary bitwise operation."""
    return ((b & c) | ((~b) & d)) & 0xFFFFFFFF

def SHA1_f2(b, c, d):
    """ Second ternary bitwise operation."""
    return (b ^ c ^ d) & 0xFFFFFFFF

def SHA1_f3(b, c, d):
    """ Third ternary bitwise operation."""
    return ((b & c) | (b & d) | (c & d) ) & 0xFFFFFFFF

def SHA1_f4(b, c, d):
    """ Forth ternary bitwise operation, = SHA1_f1."""
    return (b ^ c ^ d) & 0xFFFFFFFF



class SHA1(Hash):
    """SHA1 hashing, see https://en.wikipedia.org/wiki/SHA-1#Algorithm."""

    def __init__(self):
        self.name = "SHA1"
        self.byteorder = 'big'
        self.block_size = 64
        self.digest_size = 20
        # Initialize variables
        h0 = 0x67452301
        h1 = 0xEFCDAB89
        h2 = 0x98BADCFE
        h3 = 0x10325476
        h4 = 0xC3D2E1F0
        # Store them
        self.hash_pieces = [h0, h1, h2, h3, h4]

    def update(self,arg,hs=None, message_added_length=None):

        if hs==None:
            h0, h1, h2, h3, h4 = self.hash_pieces
        else:
            h0, h1, h2, h3, h4=hs

        # 1. Pre-processing, exactly like MD5. padding.
        # Class bytearray(): bytes can be modified
        data = bytearray(arg)
        # msg-length :64bit

        if message_added_length==None:
            orig_len_in_bits = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
        else:
            orig_len_in_bits=((message_added_length+len(data))*8)& 0xFFFFFFFFFFFFFFFF

        # 1.a. Add a single '1' bit at the end of the input bits
        # data.append(): 1 byte. So must 0x80=1000 0000
        data.append(0x80)
        # 1.b. Padding with zeros as long as the input bits length ≡ 448 (mod 512)
        while len(data) % 64 != 56:
            data.append(0)
        # 1.c. append original length in bits mod (2 pow 64) to message
        data += orig_len_in_bits.to_bytes(8, byteorder='big')
        assert len(data) % 64 == 0, "Error in padding"
        # 2. Computations
        # Process the message in successive 512-bit = 64-bytes chunks:

        # Merkle-Damgard iterated construction:
        for offset in range(0, len(data), 64):
            # compress function:

            # 2.a. 512-bits = 64-bytes chunks
            chunks = data[offset: offset + 64]
            w = [0 for i in range(80)]
            # 2.b. Break chunk into sixteen 32-bit = 4-bytes words w[i], 0 ≤ i ≤ 15
            for i in range(16):
                w[i] = int.from_bytes(chunks[4 * i: 4 * i + 4], byteorder='big')
            # 2.c. Extend the sixteen 32-bit words into eighty 32-bit words
            for i in range(16, 80):
                w[i] = leftrotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
            # 2.d. Initialize hash value for this chunk
            a, b, c, d, e = h0, h1, h2, h3, h4
            # 2.e. Main loop, cf. http://www.faqs.org/rfcs/rfc3174.html
            for i in range(80):
                if 0 <= i <= 19:
                    f = SHA1_f1(b, c, d)
                    k = 0x5A827999
                elif 20 <= i <= 39:
                    f = SHA1_f2(b, c, d)
                    k = 0x6ED9EBA1
                elif 40 <= i <= 59:
                    f = SHA1_f3(b, c, d)
                    k = 0x8F1BBCDC
                elif 60 <= i <= 79:
                    f = SHA1_f4(b, c, d)
                    k = 0xCA62C1D6

                new_a = leftrotate(a, 5) + f + e + k + w[i] & 0xFFFFFFFF
                new_c = leftrotate(b, 30)
                # Rotate the 5 variables
                a, b, c, d, e = new_a, a, new_c, c, d

            # Add this chunk's hash to result so far:
            h0 = (h0 + a) & 0xFFFFFFFF
            h1 = (h1 + b) & 0xFFFFFFFF
            h2 = (h2 + c) & 0xFFFFFFFF
            h3 = (h3 + d) & 0xFFFFFFFF
            h4 = (h4 + e) & 0xFFFFFFFF

            # compress function output:[h0,h1...,h4] (digest transform this to hash.)

        # 3. Conclusion
        # for next msg
        self.hash_pieces = [h0, h1, h2, h3, h4]

    def digest(self):
        return sum(leftshift(x, 32 * i) for i, x in enumerate(self.hash_pieces[::-1]))



def hash_SHA1(data,hashpeices=None, message_added_length=None):
    """ Shortcut function to directly receive the hex digest from SHA1(data)."""
    h = SHA1()
    if isinstance(data, str):
        print("aa")
        data = bytes(data, encoding='utf8')
    h.update(data,hashpeices, message_added_length)

    return h.hash_pieces,h.hexdigest()

def sha1padding(s,message_added_length=None):
    data = bytearray(s)
    # msg-length :64bit

    if message_added_length == None:
        orig_len_in_bits = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    else:
        orig_len_in_bits = ((message_added_length + len(data)) * 8) & 0xFFFFFFFFFFFFFFFF

    # 1.a. Add a single '1' bit at the end of the input bits
    # data.append(): 1 byte. So must 0x80=1000 0000
    data.append(0x80)
    # 1.b. Padding with zeros as long as the input bits length ≡ 448 (mod 512)
    while len(data) % 64 != 56:
        data.append(0)
    # 1.c. append original length in bits mod (2 pow 64) to message
    data += orig_len_in_bits.to_bytes(8, byteorder='big')
    assert len(data) % 64 == 0, "Error in padding"

    return bytes(data)

# 29:Break a SHA-1 keyed MAC using length extension
# S(k,m)=H(k||m) length extension attack.
def  SHA1_MAC_length_extension_attack():
    # (K||m||p1)->( (k||m||p1) || w) for any w without k

    original_msg = (b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
    key =urandom(16)

    keysize=16
    hashpeices,mac = hash_SHA1(key + original_msg)

    pad1=sha1padding(urandom(keysize)+original_msg)[keysize+len(original_msg):]
    goalmsg=key+original_msg+pad1+b';admin=true'

    # shoudong set  pad(  64-bit length)
    forgemac=hash_SHA1(b';admin=true',hashpeices,keysize+len(original_msg)+len(pad1))
    print("forge: ",forgemac)
    print("real: ",hash_SHA1(goalmsg))


