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
import MT19937
from os import urandom

CHARACTER_FREQ = { 
    'a' : 0.0651738 , 'b' : 0.0124248 , 'c' : 0.0217339 , 'd' : 0.0349835, 'e' : 0.1041442, 'f' : 0.0197881, 'g' : 0.0158610,  
    'h' : 0.0492888 , 'i' : 0.0558094 , 'j' : 0.0009033 , 'k' : 0.0050529, 'l' : 0.0331490, 'm' : 0.0202124, 'n' : 0.0564513,  
    'o' : 0.0596302 , 'p' : 0.0137645 , 'q' : 0.0008606 , 'r' : 0.0497563, 's' : 0.0515760, 't' : 0.0729357, 'u' : 0.0225134,  
    'v' : 0.0082903 , 'w' : 0.0171272 , 'x' : 0.0013692 , 'y' : 0.0145984, 'z' : 0.0007836, ' ': 0.1918182
} 

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

def Break_fixed_nonce_CTR_cts():
    lines=open('20.txt').readlines()
    ptlist=[b64decode(line) for line in lines]
    ctlist=[Implement_CTR(pt) for pt in ptlist]
    return ctlist
def Break_fixed_nonce_CTR_minlen(ctlist):
    minlen=len(ctlist[0])
    for ct in ctlist:
        if len(ct)<minlen:
            minlen=len(ct)
    return minlen
def Break_fixed_nonce_CTR_remove_then_truncate(ctlist,l):
    for ct in ctlist:
        if len(ct)==l:
            ctlist.remove(ct)
    for i in range(0,len(ctlist)):
        ctlist[i]=ctlist[i][l:]
        
    return ctlist

def Hamming_distance(b1,b2):

    r=bytes(a1^a2 for a1,a2 in zip(b1,b2))
    r=int.from_bytes(r,byteorder='little')
    c=bin(r).count('1')
    return c
def get_score(bytes_str):
    score=0
    for b in bytes_str:
        #maybe there is error. e.g. {A,B,...} frequency is different from {a,b,...}
        t=chr(b).lower()
        if t in CHARACTER_FREQ:
            score+=CHARACTER_FREQ[t]
    return score
def Break_Single_byte_XOR_cipher(ct):
    scores=[]
    for b in range(256):
        s=bytes(b^x for x in ct)
        score=get_score(s)
        res={
                'score':score,
                'key':bytes([b]),
                'pt':s
                }
        scores.append(res)
    scores=sorted(scores,key=lambda x:x['score'],reverse=True)
  
    return scores[0]['key']

def Break_repeating_key_XOR_haskeysize(ct,key_size):
    
    blocks=[b"" for i in range(key_size)]
    
    for i in range(0,len(ct)):
        blocks[i%key_size]+=bytes([ct[i]])
        
    repeatkey=b''
    for block in blocks:
        r=Break_Single_byte_XOR_cipher(block)   
        repeatkey+=r
        
    return repeatkey

def Break_fixed_nonce_CTR_statistically():
    ctlist=Break_fixed_nonce_CTR_cts()
  
    keystream=b''
    
    while len(ctlist)>0:
        l=Break_fixed_nonce_CTR_minlen(ctlist)
        linkct=b''
        for ct in ctlist:
            linkct+=ct[:l]
        repeatkey=Break_repeating_key_XOR_haskeysize(linkct,key_size=l)
        ctlist=Break_fixed_nonce_CTR_remove_then_truncate(ctlist,l)
        keystream+=repeatkey
        
    ctlist=Break_fixed_nonce_CTR_cts()

    for ct in ctlist:
        print(Implement_CTR(ct).decode())
        print(xor(ct,keystream[:len(ct)]).decode())
        print('\n')
                    

def MT19937_Stream_Cipher_encrypt(pt):
    seed=int(urandom(2).hex(),16)
    MT19937.seed_mt(seed)
    prefix=urandom(randint(4,10))
    pt=prefix+pt
    keystream=b''
    while len(keystream)<len(pt):
        keystream+=MT19937.extract_number().to_bytes(4,byteorder='little')
    ct=xor(pt,keystream)
    print(ct)
    
MT19937_Stream_Cipher_encrypt(b'AAAAAAAAAAAAAA')
            
            
            
    
       
    
    
    
    
    
    
    
    
    
    
        
        
        
    
    
    
    
    
    
    





