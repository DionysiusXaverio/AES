# Author Name: Dionysius Xaverio

import sys
from BitVector import BitVector

class AES:
    def shiftRow(self, stateArray):
        shiftedRow = [[None for x in range(4)] for x in range(4)]

        for j in range(4):
            shiftedRow[0][j] = stateArray[0][j]
        for j in range(4):
            shiftedRow[1][j] = stateArray[1][(j + 1) % 4]
        for j in range(4):
            shiftedRow[2][j] = stateArray[2][(j + 2) % 4]
        for j in range(4):
            shiftedRow[3][j] = stateArray[3][(j + 3) % 4]
        return shiftedRow

    def generate_subbyte_table(self):
        subBytesTable = []
        cons = BitVector(bitstring='01100011')
        for i in range(0, 256):
            subbyte = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            a1, a2, a3, a4 = [subbyte.deep_copy() for x in range(4)]
            subbyte ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ cons
            subBytesTable.append(int(subbyte))
        return subBytesTable

    def get_SubTable(self):
        sub1 = BitVector(bitstring='001100011')
        sub2 = BitVector(bitstring='00000101')
        for i in range(0, 256):
            subTable1 = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            a1,a2,a3,a4 = [subTable1.deep_copy() for x in range(4)]
            subTable1 ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ sub1
            self.subBytesTable.append(int(subTable1))
            subTable2 = BitVector(intVal = i, size=8)
            b1,b2,b3 = [subTable2.deep_copy() for x in range(3)]
            subTable2 = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ sub2
            check = subTable2.gf_MI(self.AES_modulus, 8)
            subTable2 = check if isinstance(check, BitVector) else 0
            self.invSubByteTable.append(int(subTable2))

    def gkey(self, keyword, round_constant, byte_sub_table):
        rotated_word = keyword.deep_copy()
        rotated_word << 8
        newword = BitVector(size=0)
        for i in range(4):
            newword += BitVector(intVal=byte_sub_table[rotated_word[8 * i:8 * i + 8].intValue()], size=8)
        newword[:8] ^= round_constant
        round_constant = round_constant.gf_multiply_modular(BitVector(intVal=0x02), self.AES_modulus, 8)
        return newword, round_constant

    def mixCol(self, statearray):
        mixed = [[0 for x in range(4)] for x in range(4)]

        for j in range(4):
            bv1 = statearray[0][j].gf_multiply_modular(BitVector(hexstring='02'), self.AES_modulus, 8)
            bv2 = statearray[1][j].gf_multiply_modular(BitVector(hexstring='03'), self.AES_modulus, 8)
            mixed[0][j] = bv1 ^ bv2 ^ statearray[2][j] ^ statearray[3][j]
        for j in range(4):
            bv1 = statearray[1][j].gf_multiply_modular(BitVector(hexstring='02'), self.AES_modulus, 8)
            bv2 = statearray[2][j].gf_multiply_modular(BitVector(hexstring='03'), self.AES_modulus, 8)
            mixed[1][j] = bv1 ^ bv2 ^ statearray[0][j] ^ statearray[3][j]
        for j in range(4):
            bv1 = statearray[2][j].gf_multiply_modular(BitVector(hexstring='02'), self.AES_modulus, 8)
            bv2 = statearray[3][j].gf_multiply_modular(BitVector(hexstring='03'), self.AES_modulus, 8)
            mixed[2][j] = bv1 ^ bv2 ^ statearray[0][j] ^ statearray[1][j]
        for j in range(4):
            bv1 = statearray[3][j].gf_multiply_modular(BitVector(hexstring='02'), self.AES_modulus, 8)
            bv2 = statearray[0][j].gf_multiply_modular(BitVector(hexstring='03'), self.AES_modulus, 8)
            mixed[3][j] = bv1 ^ bv2 ^ statearray[1][j] ^ statearray[2][j]
        return mixed

    def subBytes(self, statearray):
        for i in range(4):
            for j in range(4):
                statearray[i][j] = BitVector(intVal = self.subBytesTable[int(statearray[i][j])], size=8)
        return statearray

    def generateKeySchedule(self, key: str) -> list:
        schedule = [None for i in range(60)]
        round_constant = BitVector(intVal = 0x01, size=8)

        key_bv = BitVector(textstring=key)

        byte_sub_table = self.generate_subbyte_table()

        for i in range(8):
            schedule[i] = key_bv[i * 32: i * 32 + 32]
        for i in range(8, 60):
            if i % 8 == 0:
                kwd, round_constant = self.gkey(schedule[i - 1], round_constant, byte_sub_table)
                schedule[i] = schedule[i - 8] ^ kwd
            elif(i - (i // 8) * 8) < 4:
                schedule[i] = schedule[i - 8] ^ schedule[i - 1]
            elif (i - (i // 8) * 8) == 4:
                schedule[i] = BitVector(size=0)
                for j in range(4):
                    schedule[i] += BitVector(intVal=byte_sub_table[schedule[i - 1][8 * j:8 * j + 8].intValue()], size=8)
                schedule[i] ^= schedule[i - 8]
            elif ((i - (i // 8) * 8) > 4) and ((i - (i // 8) * 8) < 8):
                schedule[i] = schedule[i - 8] ^ schedule[i - 1]
            else:
                sys.exit(f"error in key scheduling algorithm for i = {i}")
        return schedule

    def stateArrXor(self, sa1, sa2):
        for i in range(4):
            for j in range(4):
                sa1[i][j] = sa1[i][j] ^ sa2[i][j]
        return sa1

    def invShiftedRow(self, statearray):
        shifted = [[None for x in range(4)] for x in range(4)]

        for j in range(4):
            shifted[0][j] = statearray[0][j]
        for j in range(4):
            shifted[1][j] = statearray[1][(j - 1) % 4]
        for j in range(4):
            shifted[2][j] = statearray[2][(j - 2) % 4]
        for j in range(4):
            shifted[3][j] = statearray[3][(j - 3) % 4]
        return shifted

    def invMixCol(self, statearray):
        mixed = [[0 for x in range(4)] for x in range(4)]

        for j in range(4):
            bv1 = statearray[0][j].gf_multiply_modular(BitVector(hexstring='0e'), self.AES_modulus, 8)
            bv2 = statearray[1][j].gf_multiply_modular(BitVector(hexstring='0b'), self.AES_modulus, 8)
            bv3 = statearray[2][j].gf_multiply_modular(BitVector(hexstring='0d'), self.AES_modulus, 8)
            bv4 = statearray[3][j].gf_multiply_modular(BitVector(hexstring='09'), self.AES_modulus, 8)
            mixed[0][j] = bv1 ^ bv2 ^ bv3 ^ bv4
        for j in range(4):
            bv1 = statearray[0][j].gf_multiply_modular(BitVector(hexstring='09'), self.AES_modulus, 8)
            bv2 = statearray[1][j].gf_multiply_modular(BitVector(hexstring='0e'), self.AES_modulus, 8)
            bv3 = statearray[2][j].gf_multiply_modular(BitVector(hexstring='0b'), self.AES_modulus, 8)
            bv4 = statearray[3][j].gf_multiply_modular(BitVector(hexstring='0d'), self.AES_modulus, 8)
            mixed[1][j] = bv1 ^ bv2 ^ bv3 ^ bv4
        for j in range(4):
            bv1 = statearray[0][j].gf_multiply_modular(BitVector(hexstring='0d'), self.AES_modulus, 8)
            bv2 = statearray[1][j].gf_multiply_modular(BitVector(hexstring='09'), self.AES_modulus, 8)
            bv3 = statearray[2][j].gf_multiply_modular(BitVector(hexstring='0e'), self.AES_modulus, 8)
            bv4 = statearray[3][j].gf_multiply_modular(BitVector(hexstring='0b'), self.AES_modulus, 8)
            mixed[2][j] = bv1 ^ bv2 ^ bv3 ^ bv4
        for j in range(4):
            bv1 = statearray[0][j].gf_multiply_modular(BitVector(hexstring='0b'), self.AES_modulus, 8)
            bv2 = statearray[1][j].gf_multiply_modular(BitVector(hexstring='0d'), self.AES_modulus, 8)
            bv3 = statearray[2][j].gf_multiply_modular(BitVector(hexstring='09'), self.AES_modulus, 8)
            bv4 = statearray[3][j].gf_multiply_modular(BitVector(hexstring='0e'), self.AES_modulus, 8)
            mixed[3][j] = bv1 ^ bv2 ^ bv3 ^ bv4
        return mixed

    def invSubByte(self, statearray):
        for i in range(4):
            for j in range(4):
                statearray[i][j] = BitVector(intVal = self.invSubByteTable[int(statearray[i][j])], size=8)
        return statearray

    # class constructor - when creating an AES object , the
    # class ’s constructor is executed and instance variables
    # are initialized
    def __init__(self, keyfile: str) -> None:
        self.AES_modulus = BitVector(bitstring='100011011')
        self.subBytesTable = []
        self.invSubByteTable = []

        key = open(keyfile)
        self.key_str = key.read()

    # encrypt - method performs AES encryption on the plaintext and writes the ciphertext to disk
    # Inputs : plaintext (str) - filename containing plaintext
    #          ciphertext (str) - filename containing ciphertext
    # Return : void
    def encrypt (self, plaintext :str, ciphertext :str) -> None:
        key_schedule = self.generateKeySchedule(self.key_str)
        self.get_SubTable()
        bv = BitVector(filename=plaintext)
        output_file = open(ciphertext, 'w')
        while bv.more_to_read:
            bitvec = bv.read_bits_from_file(128)
            bitvec.pad_from_right(128 - bitvec.length())

            statearray = [[0 for x in range(4)] for x in range(4)]
            for i in range(4):
                for j in range(4):
                    statearray[i][j] = bitvec[32*j + 8*i:32*j + 8 * (i + 1)]

            key_array = [[0 for x in range(4)] for x in range(4)]
            for j in range(4):
                keyword = key_schedule[j]
                for i in range(4):
                    key_array[i][j] = keyword[i * 8:i * 8 + 8]

            statearray = self.stateArrXor(statearray, key_array)

            for roundNum in range(14):

                key_array = [[0 for x in range(4)] for x in range(4)]
                for j in range(4):
                    roundkw = key_schedule[j + 4 * (roundNum + 1)]
                    for i in range(4):
                        key_array[i][j] = roundkw[i * 8:i * 8 + 8]

                statearray = self.subBytes(statearray)
                statearray = self.shiftRow(statearray)

                if roundNum != 13:
                    statearray = self.mixCol(statearray)

                statearray = self.stateArrXor(statearray, key_array)

            for j in range(4):
                for i in range(4):
                    bv_to_print = statearray[i][j]
                    hexstr = bv_to_print.get_hex_string_from_bitvector()
                    output_file.write(hexstr)

    # decrypt - method performs AES decryption on the ciphertext and writes the recovered plaintext to disk
    # Inputs : ciphertext (str) - filename containing ciphertext
    #          decrypted (str) - filename containing recovered plaintext
    # Return : void
    def decrypt (self, ciphertext :str, decrypted :str) -> None:

        key_schedule = self.generateKeySchedule(self.key_str)

        self.get_SubTable()

        bv = BitVector(filename=ciphertext)
        output_file = open(decrypted, 'wb')

        while bv.more_to_read:
            encrypted_text = bv.read_bits_from_file(256)
            bitvec = BitVector(hexstring=encrypted_text.get_bitvector_in_ascii())

            bitvec.pad_from_right(128 - bitvec.length())

            stateArray = [[0 for x in range(4)] for x in range(4)]
            for i in range(4):
                for j in range(4):
                    stateArray[i][j] = bitvec[32 * j + 8 * i:32 * j + 8 * (i + 1)]

            key_array = [[0 for x in range(4)] for x in range(4)]
            for j in range(4):
                keyword = key_schedule[56 + j]
                for i in range(4):
                    key_array[i][j] = keyword[i * 8:i * 8 + 8]

            stateArray = self.stateArrXor(stateArray, key_array)

            for roundNum in range(14):
                key_array = [[0 for x in range(4)] for x in range(4)]
                for j in range(4):
                    roundkm = key_schedule[j + 52 - 4 * roundNum]
                    for i in range(4):
                        key_array[i][j] = roundkm[i * 8:i * 8 + 8]

                stateArray = self.invShiftedRow(stateArray)
                stateArray = self.invSubByte(stateArray)
                stateArray = self.stateArrXor(stateArray, key_array)
                if roundNum != 13:
                    stateArray = self.invMixCol(stateArray)

            for j in range(4):
                for i in range(4):
                    bv_to_print = stateArray[i][j]
                    bv_to_print.write_to_file(output_file)

if __name__ ==  '__main__' :
    cipher = AES(keyfile = sys.argv[3])
    if sys.argv [1] == "-e":
        cipher.encrypt ( plaintext = sys.argv[2], ciphertext = sys.argv[4])
    elif sys.argv [1] == "-d":
        cipher.decrypt ( ciphertext = sys.argv [2], decrypted = sys.argv[4])
    else:
        sys.exit (" Incorrect Command - Line Syntax ")
