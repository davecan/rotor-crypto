# Mimics a multi-rotor device such as the Enigma.
#
# When initialized it must be passed a key consisting of a list of rotors,
# and a same-sized list of speeds -- each speed index corresponds to that rotor index.
# Each rotor is rotated by its corresponding value from rotation_speeds.
# This allows rotors to move at varying speeds with each "keypress".
#
# NOTE: This is NOT a simulation of the Enigma itself.
# In this implementation the next rotor is rotated immediately after the previous rotor rotates.
# The Enigma rotation scheme worked differently.
#
# Obviously this would be susceptible to a ciphertext-only attack
class MultiRotorDevice:
    __alphabet = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789. ')
    __key = []  # key contains 1..n rotors
    __speeds = []
    __cur_rotor_idx = 0

    __tracing = False

    def __init__(self, key, rotation_speeds):
        self.__key = [list(k) for k in key]
        self.__speeds = rotation_speeds
        if self.__tracing: self.__show_rotors()

    def enable_tracing(self):
        self.__tracing = True

    def __show_rotors(self):
        print('*'*10,'rotors','*'*10)
        for rotor in self.__key:
            print(''.join(rotor))
        print('*'*10,'/rotors','*'*10)

    def __rotate(self):
        if self.__tracing: print('-'*10,'rotate....')
        rotor = self.__current_rotor()
        speed = self.__speeds[self.__cur_rotor_idx]
        if self.__tracing: print('rotating rotor by %s:   ' % speed, ''.join(rotor))
        for i in range(0, speed):
            rotor.append(rotor.pop(0))  # rotate left ("up")
        if self.__tracing: self.__show_rotors()

    def __current_rotor(self):
        return self.__key[self.__cur_rotor_idx]

    def __next_rotor(self):
        self.__cur_rotor_idx = (self.__cur_rotor_idx + 1) % len(self.__key)  # rotate list of rotors infinitely
        return self.__current_rotor()

    def encrypt(self, plaintext):
        # normalize to only uppercase letters, trimmed non-embedded whitespace, removed other symbols
        msg = plaintext.strip().upper()
        msg = ''.join(e for e in msg if e.isalnum() or e in [' ', '.'])

        if self.__tracing: print('\n\n','='*10,'encrypting...')

        ciphertext = ''
        for char in msg:
            if self.__tracing: print('-'*10,'char -> %s' % char)
            i = self.__alphabet.index(char)
            rotor = self.__next_rotor()
            if self.__tracing: print('rotor:', ''.join(rotor))
            ciphertext += rotor[i]
            if self.__tracing: print('ciphertext:', ciphertext)
            self.__rotate()
        return ciphertext

    def decrypt(self, ciphertext):
        if self.__tracing: print('\n\n','='*10,'decrypting...')
        msg = ''
        for char in ciphertext:
            rotor = self.__next_rotor()
            if self.__tracing: print('rotor:', ''.join(rotor))
            i = rotor.index(char)
            if self.__tracing: print('char at rotor position', i)
            msg += self.__alphabet[i]
            self.__rotate()
        return msg


# generate a random set of rotors for the key each time
# realistically this key would have to be stored and reused by both sender and receiver
import random
alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789. '
key = []
for i in range(0,6):
    key.append(random.sample(alphabet, len(alphabet)))

speeds = [3,1,5,2,6,4]

alice = MultiRotorDevice(key, speeds)
p = "Attack location 8675309 at dawn. Do not engage enemy before then."
c = alice.encrypt(p)

print('plaintext:  ',p)
print('ciphertext: ',c)

bob = MultiRotorDevice(key, speeds)
m = bob.decrypt(c)
print('bob sees:', m)

# SIMULATE ATTACKER
# knows 0 rotors, 0 speeds
key2 = [random.sample(alphabet,len(alphabet))]
eve = MultiRotorDevice(key2, [1])
print('eve 0 rotors 0 speeds:',eve.decrypt(c))

# knows first rotor, 0 speeds
key2 = [key[0]]
for i in range(0,5):
    key2.append(random.sample(alphabet, len(alphabet)))
eve = MultiRotorDevice(key2, [1,1,1,1,1,1])
print('eve first rotor, 0 speeds:',eve.decrypt(c))

# knows first rotor, first speed
key2 = [key[0]]
for i in range(0,5):
    key2.append(random.sample(alphabet, len(alphabet)))
eve = MultiRotorDevice(key2, [3,1,1,1,1,1])
print('eve first rotor, first speed:',eve.decrypt(c))

# knows rotors 1-2, speeds 1-2
key2 = [key[0], key[1]]
for i in range(0,4):
    key2.append(random.sample(alphabet, len(alphabet)))
eve = MultiRotorDevice(key2, [3,1,1,1,1,1])
print('eve rotor 1-2, speed 1-2:',eve.decrypt(c))

# knows 5 rotors and 5 speeds
# This is the first point at which the cipher can be partially read
key2 = list(key)
key2[5] = random.sample(alphabet, len(alphabet))
eve = MultiRotorDevice(key2, [3,1,5,2,6,1])
print('eve 5 rotors and 5 speeds:',eve.decrypt(c))

# knows 6 rotors but only 5 speeds
# Much closer!
key2 = list(key)
eve = MultiRotorDevice(key2, [3,1,5,2,6,1])
print('eve 6 rotors and 5 speeds:',eve.decrypt(c))

# knows 5 rotors but all 6 speeds
key2 = list(key)
key2[5] = random.sample(alphabet, len(alphabet))
eve = MultiRotorDevice(key2, speeds)
print('eve 5 rotors and 6 speeds:',eve.decrypt(c))