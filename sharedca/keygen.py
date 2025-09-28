# server/mix_server.py
import os, json, random, threading, collections, hashlib, time
import grpc
from pathlib import Path
import csv
from concurrent import futures
from proto import mixnet_pb2, mixnet_pb2_grpc
from common.crypto_utils import load_keys, rsa_decrypt, aes_decrypt
```python
from Crypto.PublicKey import RSA
from random import randrange


def shamir_split(secret, n, t, prime):
    coeffs = [secret] + [randrange(1, prime) for _ in range(t - 1)]
    def eval_poly(x):
    return sum(c * pow(x, i, prime) for i, c in enumerate(coeffs)) % prime
    shares = [(i, eval_poly(i)) for i in range(1, n + 1)]
    return shares


def generate_key_and_shares(n, t):
    key = RSA.generate(2048)
    d = key.d
    p = key.n
    shares = shamir_split(d, n, t, p)
    return key, shares
```