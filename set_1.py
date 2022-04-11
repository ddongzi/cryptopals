#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Apr  9 00:03:20 2022

@author: dong
"""
from base64 import b64encode
from base64 import b64decode

from Cryptodome.Cipher import AES

CHARACTER_FREQ = { 
    'a' : 0.0651738 , 'b' : 0.0124248 , 'c' : 0.0217339 , 'd' : 0.0349835, 'e' : 0.1041442, 'f' : 0.0197881, 'g' : 0.0158610,  
    'h' : 0.0492888 , 'i' : 0.0558094 , 'j' : 0.0009033 , 'k' : 0.0050529, 'l' : 0.0331490, 'm' : 0.0202124, 'n' : 0.0564513,  
    'o' : 0.0596302 , 'p' : 0.0137645 , 'q' : 0.0008606 , 'r' : 0.0497563, 's' : 0.0515760, 't' : 0.0729357, 'u' : 0.0225134,  
    'v' : 0.0082903 , 'w' : 0.0171272 , 'x' : 0.0013692 , 'y' : 0.0145984, 'z' : 0.0007836, ' ': 0.1918182
} 


def Convert_hex_to_base64(hex_str):
    s=bytes.fromhex(hex_str)
    base64_str=b64encode(s)
    return base64_str

def Fixed_XOR(a,b):

    res=bytes(x^y for x,y in zip(a,b) )       
    return res

def get_score(bytes_str1):
    score=0
    for b in bytes_str1:
        t=chr(b).lower()
        if t in CHARACTER_FREQ:
            score+=CHARACTER_FREQ[t]
    return score
"""
a:bytes
return:{'score':_,'key':_,'pt':_}
"""
def Single_byte_XOR_cipher(a):
    
    scores=[]
    for b in range(256):
        s=bytes(b^x for x in a)
        score=get_score(s)
        res={
                'score':score,
                'key':bytes([b]).hex(),
                'pt':s.hex()
                }
        scores.append(res)
    scores=sorted(scores,key=lambda x:x['score'],reverse=True)

    return scores[0]
def Detect_single_character_XOR():
    
    fp=open('4.txt',mode='r')
    lines=fp.readlines()
    res_list=[]
    for l in lines:
        d=Single_byte_XOR_cipher(l)
        res={
                'ct':l,
                'best_single_key':d
                }
        res_list.append(res)
    res_list=sorted(res_list,key=lambda x:x['best_single_key']['score'],reverse=True)

    return res_list[0]
'''
s:bytes
k:bytes
return:hex str
'''
def Implement_repeating_key_XOR(bs,repeat_key):

    l=len(repeat_key)
    
    res=bytes(bs[i]^repeat_key[i%l] for i in range(len(bs)))
    return res.hex()

'''
s1,s2: bytes.  same len.

'''

def  Hamming_distance(b1,b2):

    r=bytes(a1^a2 for a1,a2 in zip(b1,b2))
    r=int.from_bytes(r,byteorder='little')
    c=bin(r).count('1')
    return c


def Break_repeating_key_XOR():
    with open('6.txt',mode='r') as fp:
        s=fp.read()
        s=b64decode(s)
    #guess key size.
    c_s=[]
    for key_size in range(2,40):
        
        block = [s[i:i+key_size] for i in range(0,len(s)-key_size,key_size)]

        distances=[]
        for i in range(len(block)-1):
            s1=block[i]
            s2=block[i+1]
            dist=Hamming_distance(s1,s2)
            distance=dist/key_size
            distances.append(distance)
        normal_distance=sum(distances)/len(distances)
        r={
                'key_size':key_size,
                'normal_distance':normal_distance
                }
        c_s.append(r)
    
    #!!smallest distance -key  with high prob.(take much time check)
    c_s=sorted(c_s,key=lambda x:x['normal_distance'])
    
    keysize_list=[]
    for i in range(1):
        keysize_list.append(c_s[i]['key_size'])
    
    for key_size in keysize_list:
        
        blocks=["" for i in range(key_size)]
        
        for i in range(0,len(s)):

            blocks[i%key_size]+=bytes([s[i]]).hex()
            
        key=""
        for block in blocks:
            r=Single_byte_XOR_cipher(bytes.fromhex(block))   
            key+=r['key']
        
        res=Implement_repeating_key_XOR(s,bytes.fromhex(key))

        print("keysize : {} \nkey : {} \npt: {} \n".format(key_size,bytes.fromhex(key).decode(),bytes.fromhex(res).decode()))
    

        

    
    
    
    
    
    
    
    
    

    