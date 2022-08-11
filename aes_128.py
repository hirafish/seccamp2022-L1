def hex_to_bin(s: str) -> str:
    m = bin(int(s, 16))[2:].zfill(128)
    return m


def int_list_to_hex(l: list):
    tmp = []
    for i in l:
        tmp.append(hex(i)[2:].zfill(2))
    return "".join(tmp)

class AES_128:

    aes_sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]

    aes_inv_sbox = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]

    rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    AES_POLYTON = 0b100011011

    def __init__(self, plaintext, key, N):
        self.plaintext = plaintext
        self.key = key
        self.N = N

    def make_round_key(self, key:str) -> list:
        kw = 4
        w = []
        for i in range(kw):
            w.append(key[i*32:(i+1)*32])
        i = 1
        while i <= 10:
            wn = []
            for j in range(1, 4):
                tmp = int(w[4*i-1][8*j:8*(j + 1)], 2)
                sb = self.aes_sbox[tmp]
                if j == 1:
                    wn.append(bin(sb ^ self.rcon[i])[2:].zfill(8))
                else:
                    wn.append(bin(sb)[2:].zfill(8))

            j = 0
            tmp = int(w[4*i-1][8*j:8*(j + 1)], 2)
            sb = self.aes_sbox[tmp]
            wn.append(bin(sb)[2:].zfill(8))

            wn = "".join(wn)
            for j in range(4):
                w.append(bin(int(w[4*(i-1)+j], 2) ^ int(wn, 2))[2:].zfill(32))
                wn = w[-1]

            i += 1
            # print(w)
        key = []
        for i in range(0, 11):
            tmp = w[4*i] + w[4*i + 1] + w[4*i + 2] + w[4*i + 3]
            for j in range(16):
                key.append(int(tmp[8*j:8*(j + 1)], 2))
        return key

    @classmethod
    def inv_make_round_key(self, key: list, round: int) -> list:
        inv_round_key = []
        inv_round_key.append(key)

        while round >= 1:
            bin_128 = []
            for i in range(16):
                bin_128.append(bin(key[i])[2:].zfill(8))
            bin_128 = "".join(bin_128)

            w = []
            for i in range(4):
                w.append(bin_128[i*32:(i+1)*32])
            round_key = []
            round_key.append(bin(int(w[-1], 2) ^ int(w[-2], 2))[2:].zfill(32))
            round_key.append(bin(int(w[-2], 2) ^ int(w[-3], 2))[2:].zfill(32))
            round_key.append(bin(int(w[-3], 2) ^ int(w[-4], 2))[2:].zfill(32))
            wn = bin(self.aes_sbox[int(round_key[0][8:16], 2)] ^ self.rcon[round])[2:].zfill(8) + bin(self.aes_sbox[int(round_key[0][16:24], 2)])[2:].zfill(8) + bin(self.aes_sbox[int(round_key[0][24:], 2)])[2:].zfill(8) + bin(self.aes_sbox[int(round_key[0][:8], 2)])[2:].zfill(8)
            round_key.append(bin(int(w[-4], 2) ^ int(wn, 2))[2:].zfill(32))
            round_key = round_key[::-1]

            key_tmp = []
            for i in range(4):
                for j in range(4):
                    key_tmp.append(int(round_key[i][j*8:(j+1)*8], 2))
            key = key_tmp
            inv_round_key.append(key_tmp)
            round -= 1

        inv_round_key = inv_round_key[::-1]
        return inv_round_key


    def transpose(self, message: list) -> list:
        """
        messageを転置するだけ、
        転置した後は1次元の配列
        bit単位のまま
        """
        m = []
        tmp = []
        fl = 0
        for i in range(16):
            tmp.append(message[i])
            fl += 1
            if fl == 4:
                m.append(tmp)
                tmp = []
                fl = 0
        l = list(list(zip(*m)))
        t_list = []
        for i in l:
            for j in range(4):
                t_list.append(i[j])
        # print(t_list)
        return t_list


    def AddRoundKey(self, m: list, round: int, key: list) -> list:
        # print("これはaddkeyです")
        # print("".join(map(lambda x: '%02x' % x, key[round*16:(round + 1)*16])))
        w = self.transpose(key[round*16:(round + 1)*16])
        c = []
        for i in range(16):
            c.append(m[i] ^ w[i])
        return c


    def SubBytes(self, matrix: list) -> list:
        m_list = []
        for i in range(16):
            m_list.append(self.aes_sbox[matrix[i]])
        return m_list


    def ShiftRows(self, matrix: list) -> list:
        m_list = []
        m_list.append(matrix[0])
        m_list.append(matrix[1])
        m_list.append(matrix[2])
        m_list.append(matrix[3]) 
        m_list.append(matrix[5])
        m_list.append(matrix[6])
        m_list.append(matrix[7])
        m_list.append(matrix[4])
        m_list.append(matrix[10])
        m_list.append(matrix[11])
        m_list.append(matrix[8])
        m_list.append(matrix[9]) 
        m_list.append(matrix[15])
        m_list.append(matrix[12])
        m_list.append(matrix[13])
        m_list.append(matrix[14])
        return m_list


    def inv_ShiftRows(self, matrix: list) -> list:
        m_list = []
        m_list.append(matrix[0])
        m_list.append(matrix[1])
        m_list.append(matrix[2])
        m_list.append(matrix[3]) 
        m_list.append(matrix[5])
        m_list.append(matrix[6])
        m_list.append(matrix[7])
        m_list.append(matrix[4])
        m_list.append(matrix[10])
        m_list.append(matrix[11])
        m_list.append(matrix[8])
        m_list.append(matrix[9]) 
        m_list.append(matrix[15])
        m_list.append(matrix[12])
        m_list.append(matrix[13])
        m_list.append(matrix[14])
        return m_list


    def GF_double(self, form: int) -> int:
        t = form * 2
        if (t >> 8) & 1 == 1:
            t ^= self.AES_POLYTON
        return t    


    def GF_triple(self, form: int) -> int:
        t = self.GF_double(form)
        tri = t ^ form
        return tri


    def MixColumns(self, matrix: list) -> list:
        m_list = []
        matrix = self.transpose(matrix)
        for i in range(4):
            m_list.append(self.GF_double(matrix[i*4]) ^ self.GF_triple(matrix[i*4 + 1]) ^                matrix[i*4 + 2]  ^                matrix[i*4 + 3])
            m_list.append(               matrix[i*4]  ^ self.GF_double(matrix[i*4 + 1]) ^ self.GF_triple(matrix[i*4 + 2]) ^                matrix[i*4 + 3])
            m_list.append(               matrix[i*4]  ^                matrix[i*4 + 1]  ^ self.GF_double(matrix[i*4 + 2]) ^ self.GF_triple(matrix[i*4 + 3]))
            m_list.append(self.GF_triple(matrix[i*4]) ^                matrix[i*4 + 1]  ^                matrix[i*4 + 2]  ^ self.GF_double(matrix[i*4 + 3]))
        return self.transpose(m_list)


    def encrypt(self) -> list:
        key = self.key
        plaintext = self.plaintext
        N = self.N
        # key = input("鍵を入力")
        if len(str(key)) != 128:
            key = hex_to_bin(key)
        # plaintext = input("平文を入力")
        # plaintext = '54776F204F6E65204E696E652054776F'
        p_text = plaintext
        if len(str(plaintext)) != 128:
            plaintext = hex_to_bin(plaintext)
        m = []
        for i in range(16):
            m.append(int(plaintext[i*8:(i+1)*8], 2))
        #####################mはint型を値に持つ１次元配列#####################
        key = self.make_round_key(key)
        # print("key: ", key[:80])
        round = 0
        m = self.transpose(m)
        m = self.AddRoundKey(m, round, key)
        round += 1

        while round <= (N - 1):

            # print(f"==========ROUND{round}==========")

            m = self.SubBytes(m)
            test_m = int_list_to_hex(self.transpose(m)).zfill(32)
            # print(f"SubBytes:{test_m}")

            m = self.ShiftRows(m)
            test_m = int_list_to_hex(self.transpose(m)).zfill(32)
            # print(f"ShiftRows:{test_m}")

            m = self.MixColumns(m)
            test_m = int_list_to_hex(self.transpose(m)).zfill(32)
            # print(f"MixColumns:{test_m}")
            
            m = self.AddRoundKey(m, round, key)
            # print(f"AddRoundKey:{int_list_to_hex(self.transpose(m))}")
            round += 1

        #最終ラウンド
        m = self.SubBytes(m)
        m = self.ShiftRows(m)
        m = self.AddRoundKey(m, round, key)


        return self.transpose(m)

if __name__ == '__main__':
    aes128 = AES_128(plaintext='54776F204F6E65204E696E652054776F', key='5468617473206D79204B756E67204675', N=10)
    cipher_list = aes128.encrypt()
    print("29c3505f571420f6402299b31a02d73a" == int_list_to_hex(cipher_list))