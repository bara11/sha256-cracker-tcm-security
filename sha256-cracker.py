#! /usr/bin/env python3
from base64 import decode
from pwn import * 
import sys
if len(sys.argv) !=2:
    print("Invalid arguments!")
print (">> {} <sha256sum>".format(sys.argv[0]))
wanted_hash=sys.argv[1]
print(wanted_hash)
password_file="rockyou.txt"
attemtps=0
with log.progress("Attempting to back: {}!\n".format(wanted_hash))as p :
   with open(password_file,"r",encoding='latin-1')as password_list:
     for password in password_list:
        password=password.strip("\n").encode('latin-1')
        password_hash=sha256sumhex(password)
        p.status("[{}] {} ={}"format(attemtps,password.decode('latin-1'),password_hash))
        if password_hash == wanted_hash:
             p.success("Password hash found after {} attempts! {} hashes to {}!".format(attemtps,password.decode('latin-1'),password_hash))
             exit()
        attemtps+=1
    p.failure("Password hash not found!")
