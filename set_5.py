#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on 2022/4/13 下午9:25 

@author: dong
"""
import gmpy2
from gmpy2 import mpz, random_state, mpz_random, powmod
from random import randint
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA1
from os import urandom
from set_3 import PKCS7_padding, PKCS7_padding_validation


# 33:Implement Diffie-Hellman
def Diffie_Hellman():
    p = 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
fffffffffffff'
    p = mpz(p, 16)
    print(p)
    g = 2
    a = mpz_random(random_state(), p)
    g_a = powmod(g, a, p)
    b = mpz_random(random_state(), p)
    g_b = powmod(g, b, p)

    key = powmod(g_b, a, p)
    print(key)
    key = powmod(g_a, b, p)
    print(key)


# 34:
def DH_MITM_attack():
    # A->M:
    p = 37
    g = 5
    a = randint(1, p)
    A = powmod(g, a, p)

    # M->B:
    m_a = randint(1, p)
    m_A = powmod(g, m_a, p)

    # B->M:
    b = randint(1, p)
    B = powmod(g, b, p)
    sb = powmod(m_A, b, p)

    # M->A:
    m_sb = powmod(B, m_a, p)
    m_b = randint(1, p)
    m_B = powmod(g, m_b, p)
    m_sa = powmod(A, m_b, p)

    # A->M:
    sa = powmod(m_B, a, p)
    msg = b'hello'
    iva = urandom(16)
    cta = AES.new(SHA1.new(gmpy2.to_binary(sa)).digest()[:16], AES.MODE_CBC, iva).encrypt(PKCS7_padding(msg))
    print("A send: ", iva + cta, " msg: ", msg)

    # M->B:
    ptm = AES.new(SHA1.new(gmpy2.to_binary(m_sa)).digest()[:16], AES.MODE_CBC, iva).decrypt(cta)
    isvalid, mmsg = PKCS7_padding_validation(ptm)
    print("M receive,dec: ", ptm)
    ivm = urandom(16)
    ctm = AES.new(SHA1.new(gmpy2.to_binary(m_sb)).digest()[:16], AES.MODE_CBC, ivm).encrypt(PKCS7_padding(mmsg))
    print("M relay :", ivm + ctm, "msg:", mmsg)

    # B->M:
    ptb = AES.new(SHA1.new(gmpy2.to_binary(sb)).digest()[:16], AES.MODE_CBC, ivm).decrypt(ctm)
    isvalid, echomsg = PKCS7_padding_validation(ptb)
    print("B recieve,dec: ", echomsg)
    ivb = urandom(16)
    ctb = AES.new(SHA1.new(gmpy2.to_binary(sb)).digest()[:16], AES.MODE_CBC, ivb).encrypt(PKCS7_padding(echomsg))
    print("B send: ", ivb + ctb, " msg:", echomsg)

    # M->A:
    ptm = AES.new(SHA1.new(gmpy2.to_binary(m_sb)).digest()[:16], AES.MODE_CBC, ivb).decrypt(ctb)
    isvalid, mmsg = PKCS7_padding_validation(ptm
    print("M receive,dec: ", mmsg)
    ivm = urandom(16)
    ctm = AES.new(SHA1.new(gmpy2.to_binary(m_sa)).digest()[:16], AES.MODE_CBC, ivm).encrypt(PKCS7_padding(mmsg))
    print("M relay :", ivm + ctm, "msg:", mmsg)


DH_MITM_attack()
