from BitVector import *
import sys

class AES():
    def __init__(self,key):

        self.AES_modulus = BitVector(bitstring='100011011')

        # table generated in gen_table.py in notes
        self.subBytesTable = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 
                              43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 
                              71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 
                              253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 
                              113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 
                              7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 
                              27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 
                              83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 
                              74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 
                              69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 
                              146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 
                              210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 
                              61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 
                              136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 
                              10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 
                              121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 
                              244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 
                              180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 
                              62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 
                              193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 
                              155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 
                              13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]
        
        # table generated in gen_table.py in notes
        self.invSubBytesTable = [82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 
                                 129, 243, 215, 251, 124, 227, 57, 130, 155, 47, 255, 
                                 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 
                                 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 
                                 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 
                                 162, 73, 109, 139, 209, 37, 114, 248, 246, 100, 134, 
                                 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, 
                                 108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 
                                 167, 141, 157, 132, 144, 216, 171, 0, 140, 188, 211, 
                                 10, 247, 228, 88, 5, 184, 179, 69, 6, 208, 44, 30, 143, 
                                 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107, 58, 
                                 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 
                                 180, 230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 
                                 226, 249, 55, 232, 28, 117, 223, 110, 71, 241, 26, 113, 
                                 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, 
                                 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 
                                 120, 205, 90, 244, 31, 221, 168, 51, 136, 7, 199, 49, 
                                 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 127, 169, 
                                 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 
                                 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 
                                 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 
                                 225, 105, 20, 99, 85, 33, 12, 125]

        # get encryption key schedule
        with open(key, 'r') as file:
            temp = file.read()
            temp = BitVector(textstring = temp)
        key_bv = temp

        key_words = self.gen_key_schedule_256(key_bv)
        self.round_keys = self.gen_round_keys(key_words)

        print(key_words[0].get_bitvector_in_hex())
        print(self.round_keys[0].get_bitvector_in_hex())
    
    
    # function from gen_key_schedule.py in notes
    def gee(self, keyword, round_constant, byte_sub_table):
        rotated_word = keyword.deep_copy()
        rotated_word << 8
        newword = BitVector(size = 0)
        for i in range(4):
            newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
        newword[:8] ^= round_constant
        round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), self.AES_modulus, 8)
        return newword, round_constant
    
    
    # function from gen_key_schedule.py in notes
    def gen_key_schedule_256(self, key_bv):
        # We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
        # 256 bit AES. The 256-bit AES uses the first four keywords to xor the input
        # block with. Subsequently, each of the 14 rounds uses 4 keywords from the key
        # schedule. We will store all 60 keywords in the following list:
        key_words = [None for i in range(60)]
        round_constant = BitVector(intVal = 0x01, size=8)
        for i in range(8):
            key_words[i] = key_bv[i*32 : i*32 + 32]
        for i in range(8,60):
            if i%8 == 0:
                kwd, round_constant = self.gee(key_words[i-1], round_constant, self.subBytesTable)
                key_words[i] = key_words[i-8] ^ kwd
            elif (i- (i//8)*8) < 4:
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            elif (i- (i//8)*8) == 4:
                key_words[i] = BitVector(size = 0)
                for j in range(4):
                    key_words[i] += BitVector(intVal = self.subBytesTable[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
                key_words[i] ^= key_words[i-8]
            elif ((i- (i//8)*8) > 4) and ((i- (i//8)*8) < 8):
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            else:
                sys.exit("error in key scheduling algo for i = %d" % i)
        return key_words
    
    # code from main in gen_key_schedule.py in notes
    def gen_round_keys(self, key_words):
        key_schedule = []
        for word in key_words:
            keyword_in_ints = []
            for i in range(4):
                keyword_in_ints.append(word[i*8:i*8+8].intValue())
            key_schedule.append(keyword_in_ints)
        round_keys = [None for i in range(15)]
        for i in range(15):
            round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3])

        return round_keys
    

    def substitute(self, in_bv):
        sub_bv = BitVector(size=0)
        # for each byte, replace with corresponding subByteTable entry
        for i in range(16):
            byte = in_bv[i*8:(i+1)*8].intValue()
            sub_bv += BitVector(intVal=self.subBytesTable[byte], size=8)

        return sub_bv


    def inv_substitute(self, in_bv):
        sub_bv = BitVector(size=0)
        # for each byte, replace with corresponding invSubByteTable entry
        for i in range(16):
            byte = in_bv[i*8:(i+1)*8].intValue()
            sub_bv += BitVector(intVal=self.invSubBytesTable[byte], size=8)

        return sub_bv


    def row_shift(self, state_array):
        state_array[1] = state_array[1][1:] + state_array[1][:1]
        state_array[2] = state_array[2][2:] + state_array[2][:2]
        state_array[3] = state_array[3][3:] + state_array[3][:3]

        return state_array
    

    def inv_row_shift(self, state_array):
        state_array[1] = state_array[1][-1:] + state_array[1][:-1]
        state_array[2] = state_array[2][-2:] + state_array[2][:-2]
        state_array[3] = state_array[3][-3:] + state_array[3][:-3]
    
        return state_array


    def mix_cols(self, state_array):

        # make a deep copy of the original state array
        old_arr = [[],[],[],[]]
        for idx, row in enumerate(state_array):
            for val in row:
                old_arr[idx].append(BitVector(hexstring=val))
            
        x2 = BitVector(bitstring = '00000010')
        x3 = BitVector(bitstring = '00000011')
        mod = self.AES_modulus
        
        # mixing based off equations from notes
        for j in range(4):
            state_array[0][j] = old_arr[0][j].gf_multiply_modular(x2,mod,8) ^ old_arr[1][j].gf_multiply_modular(x3,mod,8) ^ old_arr[2][j] ^ old_arr[3][j]
            state_array[1][j] = old_arr[0][j] ^ old_arr[1][j].gf_multiply_modular(x2,mod,8) ^ old_arr[2][j].gf_multiply_modular(x3,mod,8) ^ old_arr[3][j]
            state_array[2][j] = old_arr[0][j] ^ old_arr[1][j] ^ old_arr[2][j].gf_multiply_modular(x2,mod,8) ^ old_arr[3][j].gf_multiply_modular(x3,mod,8)
            state_array[3][j] = old_arr[0][j].gf_multiply_modular(x3,mod,8) ^ old_arr[1][j] ^ old_arr[2][j] ^ old_arr[3][j].gf_multiply_modular(x2,mod,8)

        return state_array
    
    
    def inv_mix_cols(self, state_array):

        # make a deep copy of the original state array
        old_arr = [[], [], [], []]
        for idx, row in enumerate(state_array):
            for val in row:
                old_arr[idx].append(val)
        
        xE = BitVector(hexstring='0E')
        xB = BitVector(hexstring='0B')
        xD = BitVector(hexstring='0D')
        x9 = BitVector(hexstring='09')
        mod = self.AES_modulus
        
        # mixing based off equations from notes
        for j in range(4):
            state_array[0][j] = old_arr[0][j].gf_multiply_modular(xE,mod,8) ^ old_arr[1][j].gf_multiply_modular(xB,mod,8) ^ old_arr[2][j].gf_multiply_modular(xD,mod,8) ^ old_arr[3][j].gf_multiply_modular(x9,mod,8) 
            state_array[1][j] = old_arr[0][j].gf_multiply_modular(x9,mod,8) ^ old_arr[1][j].gf_multiply_modular(xE,mod,8) ^ old_arr[2][j].gf_multiply_modular(xB,mod,8) ^ old_arr[3][j].gf_multiply_modular(xD,mod,8)
            state_array[2][j] = old_arr[0][j].gf_multiply_modular(xD,mod,8) ^ old_arr[1][j].gf_multiply_modular(x9,mod,8) ^ old_arr[2][j].gf_multiply_modular(xE,mod,8) ^ old_arr[3][j].gf_multiply_modular(xB,mod,8)
            state_array[3][j] = old_arr[0][j].gf_multiply_modular(xB,mod,8) ^ old_arr[1][j].gf_multiply_modular(xD,mod,8) ^ old_arr[2][j].gf_multiply_modular(x9,mod,8) ^ old_arr[3][j].gf_multiply_modular(xE,mod,8)

        return state_array
    
    
    # takes bv and returns corresponding state array
    def bv_to_state(self, bv):
        hex_bv = bv.get_bitvector_in_hex()
        state_array = [[0 for i in range(4)] for i in range(4)]
        for i in range(16):
            state_array[i % 4][i // 4] = BitVector(hexstring=hex_bv[i * 2: i * 2 + 2])

        return state_array
    
    
    # takes bv and returns corresponding hexstring state array
    def bv_to_hex_state(self, bv):
        hex_bv = bv.get_bitvector_in_hex()
        state_array = [[0 for i in range(4)] for i in range(4)]
        for i in range(16):
            state_array[i % 4][i // 4] = hex_bv[i * 2: i * 2 + 2]

        return state_array
    

    # takes state array and returns correspoding bv
    def state_to_bv(self, state_array):
        ret_bv = BitVector(size = 0)
        for i in range(16):
            ret_bv += state_array[i % 4][i // 4]
        
        return ret_bv
    

    def encrypt(self, message_file, outfile):  

        # emptry string to put hex of encryption
        hex_encrypted = ""
        
        file_bv = BitVector(filename = message_file)
        while(file_bv.more_to_read):
            raw_inhex = file_bv.read_bits_from_file(128).get_bitvector_in_hex()
            bv_inhex = BitVector(hexstring = raw_inhex)
            if bv_inhex._getsize() != 128:
                bv_inhex.pad_from_right((128-bv_inhex._getsize()))

            # add first round key before first round
            word_xor_out_bv = (bv_inhex^self.round_keys[0])

            # 14 rounds of processing due to 256 bit key
            for round in range(14):
                sbox_bv = self.substitute(word_xor_out_bv)

                # put bv into state array for row and column swapping
                state_array = self.bv_to_hex_state(sbox_bv)
                state_array = self.row_shift(state_array)

                if round != 13:
                    state_array = self.mix_cols(state_array)
                    # convert state array back into bv
                    bv_mixed = BitVector(size = 0)
                    for i in range(16):
                        bv_mixed += state_array[i % 4][i // 4]
                else:
                    bv_mixed = BitVector(size = 0)
                    for i in range(16):
                        bv_mixed += BitVector(hexstring=state_array[i % 4][i // 4])

                word_xor_out_bv = bv_mixed ^ self.round_keys[round+1]

            hex_encrypted += word_xor_out_bv.get_bitvector_in_hex()

        # write output to outfile
        with open(outfile, 'w') as file:
            file.write(hex_encrypted)
        

    def decrypt(self, encrypted_file, outfile):

        # emptry string to put plaintext
        plaintext = ""

        file_bv = BitVector(filename = encrypted_file)
        while(file_bv.more_to_read):
            raw_inhex = file_bv.read_bits_from_file(256).get_bitvector_in_ascii()
            bv_inhex = BitVector(hexstring = raw_inhex)
            
            # xor with last roundkey first
            bv_xor = bv_inhex ^ self.round_keys[14]
            state_array = self.bv_to_state(bv_xor)

            # loop in reverse because opposite of encryption
            for round in range(13, -1, -1):
                state_array = self.inv_row_shift(state_array)
                bv_shifted = self.state_to_bv(state_array)
                bv_subbed = self.inv_substitute(bv_shifted)
                bv_xor = bv_subbed ^ self.round_keys[round]
                state_array = self.bv_to_state(bv_xor)
                if round != 0:
                    state_array = self.inv_mix_cols(state_array)
            
            bv_out = self.state_to_bv(state_array)
            plaintext += bv_out.get_bitvector_in_ascii()
        
        with open(outfile, 'w') as file:
            file.write(plaintext)



if __name__ == '__main__':

    # argv: mode, message, key, outputfile

    mode = sys.argv[1]

    if mode == '-e':
        cipher = AES(key=sys.argv[3])
        cipher.encrypt(message_file=sys.argv[2], outfile=sys.argv[4])
    elif mode == '-d':
        cipher = AES(key=sys.argv[3])
        cipher.decrypt(encrypted_file=sys.argv[2], outfile=sys.argv[4])
    else:
        sys.exit("Incorrect Command-Line Syntax")