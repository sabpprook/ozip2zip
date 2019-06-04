# encoding: utf-8

from Crypto.Cipher import AES
import sys

keytable = [
    b'\xD6\xDC\xCF\x0A\xD5\xAC\xD4\xE0\x29\x2E\x52\x2D\xB7\xC1\x38\x1E', # R9s / R9s Plus / R11
    b'\xD7\xDB\xCE\x1A\xD4\xAF\xDC\xE1\x39\x3E\x51\x21\xCB\xDC\x43\x21', # R11s / R11s Plus
    b'\x12\x34\x1E\xAA\xC4\xC1\x23\xCE\x19\x35\x56\xA1\xBB\xCC\x23\x2D',
    b'\xD7\xDB\xCE\x1A\xD4\xAF\xDC\x1E\x39\x3E\x51\x21\xCB\xDC\x43\x21',
    b'\xD6\xDC\xCF\x1A\xD5\xAC\xD4\xE0\x29\x4E\x52\x2D\xB7\xC2\x38\x1E',
    b'\x01\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F',
    b'\xD4\xD2\xCD\x61\xD4\xAF\xDC\xE1\x3B\x5E\x01\x22\x1B\xD1\x4D\x20', # Find X
    b'\x26\x1C\xC7\x13\x1D\x7C\x14\x81\x29\x4E\x53\x2D\xB7\x52\x38\x1E', # Find X
    b'\x17\x2B\x3E\x14\xE4\x6F\x3C\xE1\x3E\x2B\x51\x21\xCB\xDC\x43\x21', # Realme 1
    b'\xD1\xDA\xCF\x24\x35\x1C\xE4\x28\xA9\xCE\x32\xED\x87\x32\x32\x16', # Realme 1 (reserved)
    b'\x12\xCA\xC1\x12\x11\xAA\xC3\xAE\xA2\x65\x86\x90\x12\x2C\x1E\x81', # A73
    b'\xA1\xCC\x75\x11\x5C\xAE\xCB\x89\x0E\x4A\x56\x3C\xA1\xAC\x67\xC8', # A73 (reserved)
    b'\xD4\xD2\xCE\x11\xD4\xAF\xDC\xE1\x3B\x3E\x01\x21\xCB\xD1\x4D\x20', # OPPO K1
    b'\xD4\xD2\xCE\x11\xD4\xAF\xDC\xE1\x3B\x3E\x01\x21\xCB\xD1\x4D\x20', # R17 Neo (AX7 Pro)
    b'\x17\x2B\x3E\x14\xE4\x6F\x3C\xE1\x3E\x2B\x51\x21\xCB\xDC\x43\x21', # R15
]

def main():
    if len(sys.argv) != 2:
        print ('ozip2zip v1.2, coded by sabpprook\n')
        print ('usage: ozip2zip.py <*.ozip>')
        return
    decrypt(sys.argv[1])

def getkey(data):
    for tkey in keytable:
        checkley = AES.new(tkey, AES.MODE_ECB)
        dedata = checkley.decrypt(data)
        if dedata[0] == 0x50 and dedata[1] == 0x4B:
            return tkey
    return  None

def decrypt(name):
    ifs = open(name, 'rb')
    magic = ifs.read(12)
    if magic != b'OPPOENCRYPT!':
        print ('Magic not match [OPPOENCRYPT!]')
        return
    ifs.seek(0x1050, 0)
    curkey = getkey(ifs.read(16))
    if curkey == None:
        print ("Can't find the key")
        return
    ozip = AES.new(curkey, AES.MODE_ECB)

    ifs.seek(0x1050, 0)
    ofs = open(name + '.zip', 'wb')
    print ('decrypting...')
    while True:
        data = ifs.read(16)
        ofs.write(ozip.decrypt(data))
        data = ifs.read(0x4000)
        if len(data) == 0: break
        ofs.write(data)
    ofs.close()
    ifs.close()

if __name__ == '__main__':
    main()
