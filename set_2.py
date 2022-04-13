#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Apr  9 18:46:52 2022

@author: dong
"""
from set_1 import XOR
from base64 import b64decode
from Cryptodome.Cipher import AES
from random import randint
from os import urandom

BLOCK_SIZE = AES.block_size
KEY_SIZE = 16


# AES_in_ECB_mode

def AES_ECB_encrypt(pt, key):
    cipher = AES.new(key, mode=AES.MODE_ECB)
    ct = cipher.encrypt(pt)
    return ct


def AES_ECB_decrypt(ct, key):
    cipher = AES.new(key, AES.MODE_ECB)
    pt = cipher.decrypt(ct)
    return pt


def Detect_AES_in_ECB_mode(ct, blocksize):
    blocks = [ct[i:i + blocksize] for i in range(0, len(ct), blocksize)]
    return len(blocks) - len(set(blocks))


def PKCS7_padding(pt):
    l = len(pt)
    c = BLOCK_SIZE - l % BLOCK_SIZE
    pad = bytes(c for i in range(c))
    return pt + pad


def padding_then_ECB_encrypt(pt, key=b''):
    pt = PKCS7_padding(pt)
    if key == b'':
        key = gen_key(16)
    ct = AES_ECB_encrypt(pt, key)
    return ct


# Implement CBC mode
def CBC_encrypt(pt, key, iv):
    blocks = [pt[i:i + BLOCK_SIZE] for i in range(0, len(pt), BLOCK_SIZE)]
    ct = b''
    i = 0
    prev = iv
    while i < len(blocks):
        interm = XOR(prev, blocks[i])
        prev = AES_ECB_encrypt(interm, key)
        ct = ct + prev
        i = i + 1

    return iv, ct


def CBC_decrypt(iv, ct, key):
    blocks = [ct[i:i + BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
    pt = b''
    prev = iv
    i = 0
    while i < len(blocks):
        interm = AES_ECB_decrypt(blocks[i], key)
        pt += XOR(interm, prev)
        prev = blocks[i]
        i += 1
    return pt


def gen_key():
    return urandom(KEY_SIZE)


def append_pt(pt):
    prefix = urandom(randint(5, 10))
    suffix = urandom(randint(5, 10))
    return prefix + pt + suffix


def black_box_encrypt(pt):
    r = randint(0, 1)
    key = gen_key()
    iv = gen_key()
    pt = PKCS7_padding(pt)
    if r == 0:
        ct = AES_ECB_encrypt(pt, key)
        mode = 'ECB'
    else:

        iv, ct = CBC_encrypt(pt, key, iv)
        mode = 'CBC'
    return iv + ct, mode


def An_ECB_CBC_detection_oracle(pt):
    pt = append_pt(pt)
    ct, mode = black_box_encrypt(pt)
    print('use: {} ct: {}'.format(mode, ct.hex()))
    if Detect_AES_in_ECB_mode(ct, AES.block_size) > 0:
        print('ECB')
    else:
        print('CBC')
    pass


def find_block_size():
    test_Str = b'A'
    testct = padding_then_ECB_encrypt(test_Str)
    prevlen = len(testct)
    while True:
        test_Str = test_Str + b'A'
        testct = padding_then_ECB_encrypt(test_Str)
        if len(testct) != prevlen:
            blocksize = len(testct) - prevlen
            break
    return blocksize


def Byte_at_a_time_ECB_decryption(unknown_str):
    ct = padding_then_ECB_encrypt(unknown_str)

    # goal :get unknown_str=**********

    # get blocksize
    blocksize = find_block_size()

    # detect ECB
    if Detect_AES_in_ECB_mode(ct, blocksize) == 0:
        print("not ecb. return.")

    # mantime-key.cpa
    # oracle(chosenstr)

    # build dic b'AAA..A_'
    dic = {}
    key = gen_key()
    your_Str = b'A' * (blocksize - 1)
    # one-block
    for i in range(256):
        forge_Str = your_Str + bytes([i])
        dic[AES_ECB_encrypt(forge_Str, key)] = bytes([i])

    res = b''
    for b in unknown_str:
        forge_Str = your_Str + bytes([b])
        ct = AES_ECB_encrypt(forge_Str, key)
        if ct in dic:
            res = res + dic[ct]

    return res


def profile_for():
    return b"email=AAfoo@bar.com&uid=10&role=user"


def ECB_cut_and_paste():
    # goal :cookie dec is role=admin
    # method: cut forge block into 'user' block.CCA

    key = gen_key()

    cookie = padding_then_ECB_encrypt(profile_for(), key)

    forge = padding_then_ECB_encrypt(b'admin', key)
    cookie = cookie[0:len(cookie) - BLOCK_SIZE] + forge
    forge = AES_ECB_decrypt(cookie, key)
    print(forge.decode())


def Byte_at_a_time_ECB_decryption_hard(unknowstr):
    # precise
    key = gen_key()
    prefix = urandom(randint(1, 20))
    originalct = padding_then_ECB_encrypt(prefix + unknowstr, key)

    print("prefix: {}  prefix_size: {}".format(prefix, len(prefix)))

    # find blocksize
    blocksize = find_block_size()

    # find prefixsize
    prefixsize = 0

    prevct = originalct
    oraclestr = prefix + b'A' + unknowstr
    oraclect = padding_then_ECB_encrypt(oraclestr, key)
    for i in range(len(prevct)):
        if oraclect[i] != prevct[i]:
            break
    prevct = oraclect
    prefix_0 = (int)(i / blocksize)

    for i in range(2, blocksize + 2):
        oraclestr = prefix + b'A' * i + unknowstr
        oraclect = padding_then_ECB_encrypt(oraclestr, key)
        test_prev_block = prevct[prefix_0 * blocksize:(prefix_0 + 1) * blocksize]
        test_oracle_block = oraclect[prefix_0 * blocksize:(prefix_0 + 1) * blocksize]
        if test_oracle_block == test_prev_block:
            break
        prevct = oraclect
    if i == blocksize + 1:
        prefix_1 = 0
    prefix_1 = blocksize + 1 - i
    prefixsize = prefix_0 * blocksize + prefix_1

    print("find prefixsize:{}".format(prefixsize))

    # find unknown str


def PKCS7_padding_validation(s):
    num = s[-1]
    i = -num
    try:
        while i < 0:
            if s[i] != num:
                raise Exception("invalid padding.")
            i = i + 1
    except:
        print("invaild")
    else:
        s = s[:len(s) - num]
    return s


#cant understand prob.
#guess:CBC with rand.iv is not CCA secure.
def CBC_bitflipping_attacks():
    key = gen_key()
    instr = b'A' * len(b';admin=true;')
    iv, ct = CBC_bitflipping_attacks_first(instr, key)
    isadmin = CBC_bitflipping_attacks_second(iv, ct, key)
    print(len(iv + ct))


def CBC_bitflipping_attacks_first(instr, key):
    prefix = b'comment1=cooking%20MCs;userdata='
    suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
    pt = prefix + instr + suffix
    iv = gen_key()
    iv, ct = CBC_encrypt(PKCS7_padding(pt), key, iv)
    return iv, ct


def CBC_bitflipping_attacks_second(iv, ct, key):
    pt = CBC_decrypt(iv, ct, key)
    try:
        m = pt.decode()
        if m.find(';admin=true;', 0, len(m)):
            return True
    except:
        return False


CBC_bitflipping_attacks()
