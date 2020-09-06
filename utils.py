import getpass
import socket, string, random, subprocess, os
from Crypto.PublicKey import RSA

modulus_length = 2048

def read_password():
    secret_code = getpass.getpass(prompt='passphrase :', stream=None)
    return secret_code


def get_private_key(filename):
    if(os.path.isfile(filename)):
        encrypted_key = open(filename, "rb").read()
        return RSA.import_key(encrypted_key, passphrase=read_password())

    key = RSA.generate(modulus_length)
    pub_key = key.publickey()
    secret_code = read_password()

    private_key = key.exportKey()
    public_key = pub_key.exportKey()
    encrypted_key = key.export_key(passphrase=secret_code, pkcs=8, protection="scryptAndAES128-CBC")

    file_pri_out = open("update", "wb")
    file_pub_out = open("update.pub", "wb")

    file_pri_out.write(encrypted_key)
    file_pub_out.write(public_key)
    return key
