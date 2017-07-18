# Mimics a single-rotor device such as a Hebern machine.
# With each "keypress" the key rotor is rotated n positions.
# As long as the recipient has the same key rotor with same initial setting
# the message can be decrypted.
class OneRotorDevice:
    __alphabet = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789. ')
    __key = None
    __speed = 1

    def __init__(self, key, rotation_speed=1):
        self.__key = list(key)
        self.__speed = rotation_speed

    def __rotate(self, n=1):
        for i in range(0,n):
            self.__key.append(self.__key.pop(0))  # rotate left ("up")

    def encrypt(self, plaintext):
        # normalize to only uppercase letters, trimmed non-embedded whitespace, removed other symbols
        msg = plaintext.strip().upper()
        msg = ''.join(e for e in msg if e.isalnum() or e in [' ', '.'])

        ciphertext = ''
        for char in msg:
            i = self.__alphabet.index(char)
            ciphertext += self.__key[i]
            # print('cipher %s at position %s from key %s' % (self.__key[i], i, ''.join(self.__key)))
            self.__rotate(self.__speed)
        return ciphertext

    def decrypt(self, ciphertext):
        msg = ''
        for char in ciphertext:
            i = self.__key.index(char)
            msg += self.__alphabet[i]
            self.__rotate(self.__speed)
        return msg


key = 'BCDEFGHIJKLMNOPQRSTUVWXYZ0123456789. A' 
device = OneRotorDevice(key, 2)
p = "Attack location 8675309 at dawn. Do not engage enemy before then."
c = device.encrypt(p)

device2 = OneRotorDevice(key, 2)
m = device2.decrypt(c)

print('plaintext:  ',p)
print('ciphertext: ',c)
print('message:    ',m)
