#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on 2022/4/13 下午9:25 

@author: dong
"""
import gmpy2
from gmpy2 import mpz, random_state, mpz_random, powmod, mul, add, to_binary, sub, next_prime, invert,mod,root
from random import randint
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA1, SHA256, HMAC
from os import urandom
from set_3 import PKCS7_padding, PKCS7_padding_validation
from math import pow


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
    isvalid, mmsg = PKCS7_padding_validation(ptm)
    print("M receive,dec: ", mmsg)
    ivm = urandom(16)
    ctm = AES.new(SHA1.new(gmpy2.to_binary(m_sa)).digest()[:16], AES.MODE_CBC, ivm).encrypt(PKCS7_padding(mmsg))
    print("M relay :", ivm + ctm, "msg:", mmsg)


# 36:
def SRP(N, g, k, p):
    N, g, k, p = mpz(N), mpz(g), mpz(k), b'pwd'
    rs = random_state()
    rn = 10

    # C:register
    print("C: register.\n----")
    s = mpz_random(rs, rn)
    s = to_binary(s)
    hash_c = SHA256.new(s + p)
    x = mpz(hash_c.hexdigest(), 16)
    v = powmod(g, x, N)

    # C:
    a = mpz_random(rs, rn)

    # C->S:
    userid = ''
    I = (s, v)
    A = powmod(g, a, N)
    print("C: send. userId:{}, I:{},A:{}".format(userid, I, A))

    # S:
    b = mpz_random(rs, rn)
    B = add(mul(k, v), powmod(g, b, N))
    s = I[0]
    v = I[1]
    hash_s = SHA256.new(to_binary(A) + to_binary(B))
    u_s = mpz(hash_s.hexdigest(), 16)
    Ss = powmod(mul(A, powmod(v, u_s, N)), b, N)
    Ss = gmpy2.to_binary(Ss)
    hash_s.update(Ss)
    Ks = hash_s.hexdigest()

    print("S: get Ks:", Ks)

    # S->C:
    B = B
    print("S: send. B:", B)

    # C:
    hash_c = SHA256.new(to_binary(A) + to_binary(B))
    u_c = mpz(hash_c.hexdigest(), 16)
    Sc = powmod(sub(B, mul(k, powmod(g, x, N))), add(a, mul(u_c, x)), N)
    Sc = gmpy2.to_binary(Sc)

    hash_c.update(Sc)
    Kc = hash_c.hexdigest()
    print("C: get Kc: ", Kc)

    # C->S:
    hmac_c = HMAC.new(hash_c.digest(), s, SHA256)
    mac = hmac_c.digest()

    # S->C:
    hmac_s = HMAC.new(hash_s.digest(), s, SHA256)
    try:
        hmac_s.verify(mac)
        print("OK: Kc=Ks")
    except ValueError:
        print("No: Kc!=Ks")


# 39:
def RSA():
    p = 11
    q = 5
    N = mul(p, q)
    phi_N = mul(sub(p, 1), sub(q, 1))
    e = 3
    d = invert(e, phi_N)
    PK = (N, e)
    SK = (N, d)
    m = 35
    c = powmod(m, e, N)
    pt = powmod(c, d, N)
    print(pt)

# 40:
def E3_RSA_Broadcast_attack():
    N1, N2, N3 = 3 * 5, 11 * 17, 29 * 23
    N = N1 * N2 * N3
    m = 8
    print("m:",m)
    e = 3
    c1, c2, c3 = powmod(m, e, N1), powmod(m, e, N2), powmod(m, e, N3)
    b1, b2, b3 = mpz(N / N1), mpz(N / N2), mpz(N / N3)
    b1i, b2i, b3i = invert(b1, N1), invert(b2, N2), invert(b3, N3)
    c = add(add(mul(c1, mul(b1, b1i)),mul(c2, mul(b2, b2i))), mul(c3, mul(b3, b3i)))
    c=mod(c,N)
    m=root(c,3)
    m=mod(m,N)
    print("find m:",m)
E3_RSA_Broadcast_attack()