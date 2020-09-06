#!/usr/bin/env python
# coding: utf-8

from time import localtime, strftime, time
import socket
import Crypto.Random
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA384


host, port = "", 6589
authorized_keys = []


keysFile = open('authorized_keys')
for key in keysFile:
    authorized_keys.append(RSA.import_key("-----BEGIN PUBLIC KEY-----\n" + key + "\n-----END PUBLIC KEY-----"))

black_list = []


mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
mySocket.bind((host, port))



print(port)
while True:

    # Step 1 : Accept sockets

    mySocket.listen(5)
    client, adresse = mySocket.accept()
    if adresse[0] in black_list:
        client.close()

    # Step 2 : Generate session_key and sendit

    session_key = Crypto.Random.get_random_bytes(1024)
    client.send(session_key)

    # Step 3 : Wait to receiving signature
    print("Wait to receiving signature")
    hash_session_key = SHA384.new()
    hash_session_key.update(session_key)
    auth = False
    while True:
        signature = client.recv(1024)
        if(signature):
            for key in authorized_keys:
                try:
                    signer = pkcs1_15.new(key)
                    signer.verify(hash_session_key, signature)
                    # print(session_key_test)
                    auth = True
                    break
                except:
                    pass
            break
    if(not auth):
        continue

    print("signature received")
