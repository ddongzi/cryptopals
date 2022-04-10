#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Apr  9 15:37:28 2022

@author: dong
"""

#set1_6
import string
import re
from operator import itemgetter, attrgetter
import base64


def English_Scoring(t):
    latter_frequency = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .15000
    }
    return sum([latter_frequency.get(chr(i),0) for i in t.lower()])     

def Single_XOR(s,single_character) :
    t = b''
    #print(s,single_character)
    # s = bytes.fromhex(s)
    # t: the XOR'd result
    for i in s:
        t = t+bytes([i^single_character])
        # t = re.sub(r'[\x00-\x1F]+','', t) 
        #remove the ascii control characters
    return t

def ciphertext_XOR(s) :
    _data = []
    # s = bytes.fromhex(s)
    # key = ord (single_character)
    # ciphertext = b''
    # for i in s :
    #   ciphertext = ciphertext + bytes([i ^ key])
    for single_character in range(256):
        ciphertext = Single_XOR(s,single_character)
        #print(ciphertext)
        score = English_Scoring(ciphertext)
        data = {
          'Single character' : single_character,
          'ciphertext' : ciphertext,
          'score' : score
        }
        _data.append(data)
    score = sorted(_data, key = lambda score:score['score'], reverse=True)[0]
    # print(score['ciphertext'])
    return score

def Repeating_key_XOR(_message,_key) :
    cipher = b''
    length = len(_key)
    for i in range(0,len(_message)) :
        cipher = cipher + bytes([_message[i]^_key[i % length]])
        # print(cipher.hex())
    return cipher


"""
if __name__ == '__main__':
    _data = []
    s = open('cryptopals_set1_4.txt').read().splitlines()
    for i in s :
        # print(i)
        data = ciphertext_XOR(i)
        _data.append(data)
    best_score = sorted(_data, key = lambda score:score['score'], reverse=True)[0]
    print(best_score)
    for i in best_score :
        print("{}: {}".format(i.title(), best_score[i]))

    # print(f'{j}:{t},{score}')
"""


def hamming_distance(a,b) :
    distance = 0
    for i ,j in zip(a,b) :
        byte = i^j
        distance = distance + sum(k == '1' for k in bin(byte) )
    return distance

def Get_the_keysize(ciphertext) :
    data = []
    for keysize in range(2,41) :
        block = [ciphertext[i:i+keysize] for i in range(0,len(ciphertext),keysize)]
        distances = []
        for i in range(0,len(block),2) :
            try:
                block1 = block[i]
                block2 = block[i+1]
                distance = hamming_distance(block1,block2)
                distances.append(distance / keysize)
            except :
                break
        _distance = sum(distances) / len(distances)
        _data = {
            'keysize' : keysize,
            'distance': _distance
        }
        data.append(_data)
    _keysize = sorted(data, key = lambda distance:distance['distance'])
    
    # print("123456789456123",_keysize)
    #_keysize = min(data,key = lambda distance:distance['diatance'])
    return _keysize[0]



def Break_repeating_key_XOR(ciphertext):
    
    # Guess the length of the key
    _keysize = Get_the_keysize(ciphertext)
    keysize = _keysize['keysize']
    print(_keysize)
    key = b''
    cipher = b''
    block = [ciphertext[i:i+keysize] for i in range(0,len(ciphertext),keysize)]
    for i in range(0 , keysize) :
        new_block = []
        t = b''
        for j in range(0,len(block)-1) :
            s= block[j]
            t=t+bytes([s[i]])
        socre = ciphertext_XOR(t)
        key = key + bytes([socre['Single character']])
        # cipher = cipher + socre['ciphertext']
    # print(cipher)
    #for k in range(0,len(block)) :
     #   cipher = cipher+Repeating_key_XOR(block[k],key)
    # print(key)
    cipher = Repeating_key_XOR(ciphertext,key)
    return cipher,key
      # sorted(data, key = lambda distance:distance['distance'])[0]
    
 


if __name__ == '__main__' :
    with open('6.txt') as of :
        ciphertext = of.read()
        ciphertext = base64.b64decode(ciphertext)
    cipher,key = Break_repeating_key_XOR(ciphertext)
    print("cipher:",cipher,"\nkey:",key)


