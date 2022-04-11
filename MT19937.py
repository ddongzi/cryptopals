#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr 11 12:41:06 2022

@author: dong
"""
(w, n, m, r) = (32, 624, 397, 31)
a = 0x9908B0DF
(u, d) = (11, 0xFFFFFFFF)
(s, b) = (7, 0x9D2C5680)
(t, c) = (15, 0xEFC60000)
l = 18
f = 1812433253

index=n+1
lower_mask = 0x7FFFFFFF #(1 << r) - 1 // That is, the binary number of r 1's
upper_mask = 0x80000000 #lowest w bits of (not lower_mask)
state=[0 for i in range(n)]


    
#Initialed state

def seed_mt(seed):
    state[0]=seed
    for i in range(1,n):
        #0xffffffff:  s.t. 32bit
        state[i]=(f*(state[i-1]^(state[i-1]>>(w-2))) +i)&0xffffffff

def extract_number():
    global index
    
    if index>=n:
        twist()
        index=0
        
    y = state[index]
    y = y ^ ((y >> u) & d)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    y = y ^ (y >> l)

    index += 1
    return y & 0xffffffff
        
def twist():
    for i in range(n):
        x = (state[i] & upper_mask) + (state[(i+1) % n] & lower_mask)
        xA = x >> 1
        if (x % 2) != 0:
            xA = xA ^ a
        state[i] = state[(i + m) % n] ^ xA
    
    global index
    index=0
        
if __name__ == '__main__':
    print("MT19937.")





    
    
    
    
    
    
    