#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Apr 10 16:35:01 2022

@author: dong
"""
from os import urandom
from Cryptodome.Cipher import AES
from base64 import b64decode
from random import randint
import math

BLOCK_SIZE=16
#which it should save for all future encryptions
KEY=urandom(16)

def PKCS7_padding(pt):
    l=len(pt)
    c=BLOCK_SIZE-l%BLOCK_SIZE
    pad=bytes(c for i in range(c))
    return pt+pad

def PKCS7_padding_validation(s):    
    num=s[-1]
    i=-num
    isvalid=True
    try:
        if num>BLOCK_SIZE or num==0:
            raise Exception("invalid padding.")
        while i<0:
            if s[i]!=num:
                
                raise Exception("invalid padding.")
            i=i+1
    except:
        isvalid=False
    else:
        s=s[:len(s)-num] 
    return isvalid,s

def xor(a,b):
    c=bytes(x^y for x,y in zip(a,b))
    return c
# Chanllenge 17  
def first():
  
    lines=open('17.txt').readlines()
    i=randint(1,len(lines))
    s=b64decode(lines[i])
    
    print("selected pt :{}".format(s.decode()))    
    
    iv=urandom(BLOCK_SIZE)
    cipher=AES.new(KEY,AES.MODE_CBC,iv)
    pt=PKCS7_padding(s)
    ct=cipher.encrypt(pt)
    return ct,iv

#the second function models the server's consumption of an encrypted session token, as if it was a cookie. 
def second(ct,iv):
    cipher=AES.new(KEY,AES.MODE_CBC,iv)
    pt=cipher.decrypt(ct)
    
    isvalid,pt=PKCS7_padding_validation(pt)
    return isvalid,pt
    
    
def CBC_padding_oracle_attack():
    ct,iv=first()
    iv=[iv]
    blocks=[ct[i:i+BLOCK_SIZE] for i in range(0,len(ct),BLOCK_SIZE)]
    blocks=iv+blocks
    
    find_pt=b''
    for i in range(1,len(blocks)):
        block=blocks[i]
        m_i=b'0'*BLOCK_SIZE
        ct_i=block
        for k in range(1,BLOCK_SIZE+1):
            #print("find {}th to last.".format(k))
            leftblock=blocks[i-1]
                        
            if k>1:
                suffix=xor(leftblock[-k+1:],xor(m_i[-k+1:],bytes([k])*(k-1)))
            prefix=leftblock[:-k]
            mid=leftblock[-k]
            for g in range(256):
                
                leftblock=prefix+bytes([mid^g^k ])
                if k>1:
                    leftblock=leftblock+suffix
                forge_iv=leftblock
                #print("iv :{}".format(iv.hex()))
                g_isvalid,_=second(ct_i,forge_iv)
                #print("pt : {}    {} ".format(pt.hex(),isvalid))
                if g_isvalid==True:
                    guess=bytes([g])
            
            if k>1:
                m_i=m_i[:-k]+guess+m_i[-k+1:]
            else:
                m_i=m_i[:-k]+guess
        
        find_pt=find_pt+m_i
    
    _,pt=PKCS7_padding_validation(find_pt)
    print(pt.decode())
    

def Implement_CTR(s,nonce=b'0'*8):
    #s:both dec,enc
    num=math.ceil(len(s)/BLOCK_SIZE)
    keystream=b''
    cipher=AES.new(KEY,AES.MODE_ECB)
    for counter in range(num):
        IV=nonce+counter.to_bytes(length=8,byteorder='little')
        keystream=keystream+cipher.encrypt(IV)
    keystream=keystream[:len(s)]
    
    return xor(keystream,s)

    
    
    
    
    
    
    
    
    
    
    
        
        
        
    
    
    
    
    
    
    





