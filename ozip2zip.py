# encoding: utf-8

from Crypto.Cipher import AES
import sys

keytable = [
    b'\xD6\xDC\xCF\x0A\xD5\xAC\xD4\xE0\x29\x2E\x52\x2D\xB7\xC1\x38\x1E', # R9s / R9s Plus / R11
    b'\xD7\xDB\xCE\x1A\xD4\xAF\xDC\xE1\x39\x3E\x51\x21\xCB\xDC\x43\x21', # R11s / R11s Plus
    b'\x12\x34\x1E\xAA\xC4\xC1\x23\xCE\x19\x35\x56\xA1\xBB\xCC\x23\x2D',
    b'\xD7\xDB\xCE\x1A\xD4\xAF\xDC\x1E\x39\x3E\x51\x21\xCB\xDC\x43\x21',
    b'\xD6\xDC\xCF\x1A\xD5\xAC\xD4\xE0\x29\x4E\x52\x2D\xB7\xC2\x38\x1E',
]

def main():
    if len(sys.argv) != 2:
        print 'ozip2zip v1.2, coded by sabpprook\n'
        print 'usage: ozip2zip.py <*.ozip>'
        return
    decrypt(sys.argv[1])

def getkey(data):
    for tkey in keytable:
        checkley = AES.new(tkey, AES.MODE_ECB)
        dedata = checkley.decrypt(data)
        if dedata[0] == 'P' and dedata[1] == 'K':
            return tkey
    return  None

def decrypt(name):
    ifs = open(name, 'rb')
    magic = ifs.read(12)
    if magic != 'OPPOENCRYPT!':
        print 'Magic not match [OPPOENCRYPT!]'
        return
    ifs.seek(0x1050, 0)
    curkey = getkey(ifs.read(16))
    if curkey == None:
        print "Can't find the key"
        return
    ozip = AES.new(curkey, AES.MODE_ECB)

    ifs.seek(0x1050, 0)
    ofs = open(name + '.zip', 'wb')
    print 'decrypting...'
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
