# encoding: utf-8

from Crypto.Cipher import AES
import sys

def main():
    if len(sys.argv) != 2:
        print 'ozip2zip v1.0, coded by sabpprook\n'
        print 'usage: ozip2zip.py <*.ozip>'
        return
    decrypt(sys.argv[1])

def decrypt(name):
    ozip = AES.new(b'\xD6\xDC\xCF\x0A\xD5\xAC\xD4\xE0\x29\x2E\x52\x2D\xB7\xC1\x38\x1E', AES.MODE_ECB)

    ifs = open(name, 'rb')
    magic = ifs.read(12).decode('UTF-8')
    if magic != 'OPPOENCRYPT!':
        print 'Magic not match [OPPOENCRYPT!]'
        return
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
