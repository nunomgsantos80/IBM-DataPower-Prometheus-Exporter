#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from cryptography.fernet import Fernet

print("\n=== Generate encryption key ===")
key = Fernet.generate_key()
print("DP_KEY =", key.decode())

cipher = Fernet(key)

print("\n=== Encrypt password ===")
pwd = input("Enter password to encrypt: ").encode()
token = cipher.encrypt(pwd)

print("\nEncrypted password:")
print(token.decode())

print("\nUse this in datapowers.json as:")
print(f'"password_enc": "{token.decode()}"')
