#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Apr  9 18:46:52 2022

@author: dong
"""
import set_1
from base64 import b64decode
from Cryptodome.Cipher import AES
from random import randint
from os import urandom

BLOCK_SIZE=AES.block_size

#AES_in_ECB_mode
        
def AES_ECB_encrypt(pt,key):

    cipher=AES.new(key,mode=AES.MODE_ECB)
    ct=cipher.encrypt(pt)
    return ct

def AES_ECB_decrypt(ct,key):
    cipher=AES.new(key,AES.MODE_ECB)
    pt=cipher.decrypt(ct)
    return pt
    
def Detect_AES_in_ECB_mode(ct,blocksize):
    blocks=[ct[i:i+blocksize] for i in range(0,len(ct),blocksize)]
    return len(blocks)-len(set(blocks))

        

def Implement_PKCS7_padding(pt,blocksize=BLOCK_SIZE):
    l=len(pt)
    c=blocksize-l%blocksize
    pad=bytes(c for i in range(c))
    return pt+pad

def padding_then_ECB_encrypt(pt,key=b'',blocksize=BLOCK_SIZE):
    pt=Implement_PKCS7_padding(pt,blocksize)
    if key==b'':
        key=gen_key(16)
    ct=AES_ECB_encrypt(pt,key)
    return ct

#Implement CBC mode 
def Implement_CBC_encrypt(s,key,IV):
    

    blocksize=BLOCK_SIZE
    
    blocks=[s[i:i+blocksize] for i in range(0,len(s),blocksize)]
    ct=IV
    i=0
    prev=IV
    while i<len(blocks):
        
        pt=set_1.Fixed_XOR(prev,blocks[i])
        prev=AES_ECB_encrypt(pt,key)
        ct=ct+prev
        i=i+1

    return ct

def gen_key(size):
    return urandom(size)

def append_pt(pt):
    prefix=gen_key(randint(5,10))
    suffix=gen_key(randint(5,10))
    return prefix+pt+suffix

def black_box_encrypt(pt):
    r=randint(0,1)
    key=gen_key(16)
    iv=gen_key(16)
    pt=Implement_PKCS7_padding(pt)
    if r==0:
        ct=AES_ECB_encrypt(pt,key)
        mode='ECB'
    else:
        
        ct=Implement_CBC_encrypt(pt,key,iv)
        mode='CBC'
    return ct,mode

def An_ECB_CBC_detection_oracle(pt):
    pt=append_pt(pt)
    ct,mode=black_box_encrypt(pt)
    print('use: {} ct: {}'.format(mode,ct.hex()))
    if Detect_AES_in_ECB_mode(ct,AES.block_size)>0:
        print('ECB')
    else:
        print('CBC')
    pass

def find_block_size():
    test_Str=b'A'
    testct=padding_then_ECB_encrypt(test_Str)
    prevlen=len(testct)
    while True:
        test_Str=test_Str+b'A'
        testct=padding_then_ECB_encrypt(test_Str)
        if len(testct)!=prevlen:
            blocksize=len(testct)-prevlen
            break
    return blocksize

def Byte_at_a_time_ECB_decryption(unknown_str):
    
    ct=padding_then_ECB_encrypt(unknown_str)

    # goal :get unknown_str=**********
    
    #get blocksize 
    blocksize=find_block_size()
    
    #detect ECB
    if Detect_AES_in_ECB_mode(ct,blocksize)==0:
        print("not ecb. return.")
    
    # mantime-key.cpa
    # oracle(chosenstr)
    
    #build dic b'AAA..A_'
    dic={}
    key=gen_key(16)
    your_Str=b'A'*(blocksize-1)
    # one-block
    for i in range(256):
        forge_Str=your_Str+bytes([i])
        dic[AES_ECB_encrypt(forge_Str,key)]=bytes([i])
    
    res=b''
    for b in unknown_str:
        forge_Str=your_Str+bytes([b])
        ct=AES_ECB_encrypt(forge_Str,key)
        if ct in dic:
            res=res+dic[ct]
        
    return res

def profile_for():
    
    return b"email=AAfoo@bar.com&uid=10&role=user"


def ECB_cut_and_paste():
    
    #goal :cookie dec is role=admin
    #method: cut forge block into 'user' block.CCA

    
    key=gen_key(16)
    
    cookie=padding_then_ECB_encrypt(profile_for(),key)
    blocksize=BLOCK_SIZE
    forge=padding_then_ECB_encrypt(b'admin',key)
    cookie=cookie[0:len(cookie)-blocksize]+forge
    forge=AES_ECB_decrypt(cookie,key)
    print(forge.decode())
    
    
def Byte_at_a_time_ECB_decryption_hard(unknowstr):
    
    #precise
    key=gen_key(16)
    prefix=urandom(randint(1,20))
    originalct=padding_then_ECB_encrypt(prefix+unknowstr,key)
    
    print("prefix: {}  prefix_size: {}".format(prefix,len(prefix)))
    
    #find blocksize
    blocksize=find_block_size()
    
    #find prefixsize
    prefixsize=0

    prevct=originalct
    oraclestr=prefix+b'A'+unknowstr
    oraclect=padding_then_ECB_encrypt(oraclestr,key)
    for i in range(len(prevct)):
        if oraclect[i]!=prevct[i]:
            break
    prevct=oraclect
    prefix_0=(int)(i/blocksize)
    
    for i in range(2,blocksize+2):
        oraclestr=prefix+b'A'*i+unknowstr
        oraclect=padding_then_ECB_encrypt(oraclestr,key)
        test_prev_block=prevct[prefix_0*blocksize:(prefix_0+1)*blocksize]
        test_oracle_block=oraclect[prefix_0*blocksize:(prefix_0+1)*blocksize]
        if test_oracle_block==test_prev_block:
            break     
        prevct=oraclect
    if i==blocksize+1:
        prefix_1=0
    prefix_1=blocksize+1-i
    prefixsize=prefix_0*blocksize+prefix_1
    
    print("find prefixsize:{}".format(prefixsize))
    
    #find unknown str
    

def PKCS7_padding_validation(s):
    
    num=s[-1]
    i=-num
    try:
        while i<0:
            if s[i]!=num:
                raise Exception("invalid padding.")
            i=i+1
    except:
        print("invaild")
    else:
        s=s[:len(s)-num] 
    return s
    

    
    
    
    
    
    
    
    
    
    
    

        
        
    
    
    
    









