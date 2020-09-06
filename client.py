#!/usr/bin/env python
# coding: utf-8


import getpass
import socket, string, random, subprocess, os
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA384
import utils



key = utils.get_private_key('update')


host, port = "127.0.0.1", 2356 #int(input('port :'))

mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

mySocket.connect((host, port))
while True:

    # Step 1 : Receive session_key
    while True:
        session_key = mySocket.recv(1024)
        if(session_key):
            print(session_key)
            break

    # Step 2 : encrypt session_key and send it
    signer = pkcs1_15.new(key)
    signature = SHA384.new()
    signature.update(session_key)
    mySocket.send(signer.sign(signature))

    # break
