from aes_128 import *
#.はカレントディレクトリから

def make_integral_text():
    """
    integral攻撃で用いる文章集合の配列作成
    int型で len = 16
    """
    text_set = []
    for i in range(256):
        tmp = []
        all_A = i
        tmp.append(hex(all_A)[2:].zfill(2))
        for _ in range(15):
            tmp.append("00")
        text_set.append("".join(tmp))

    key = '5468617473206D79204B756E67204675'
    enc_text_set = []
    for message in text_set:
        aes_128 = AES_128(message, key, N=4)
        enc_text_set.append(aes_128.encrypt())
    return enc_text_set

if __name__ == '__main__':
    import itertools
    enc_text_set =  make_integral_text()
    cand = []
    for block in range(16):
        cand_block = []
        for cand_tmp in range(256):
            tmp = 0
            for i in range(256):
                tmp ^= AES_128.aes_inv_sbox[enc_text_set[i][block] ^ cand_tmp]
            if tmp == 0:
                cand_block.append(cand_tmp)
                # break
        cand.append(cand_block)

    test_p_text = '54776F204F6E65204E696E652054776F'
    test_key = '5468617473206D79204B756E67204675'
    aes_128 = AES_128(test_p_text, test_key, N=4)
    test_c_text = aes_128.encrypt()

    for i in itertools.product(*cand):
        key = AES_128.inv_make_round_key(list(i), 4)[0]
        bin_128 = []
        for i in range(16):
            bin_128.append(bin(key[i])[2:].zfill(8))
        key_tmp = "".join(bin_128)
        aes_128_tmp = AES_128(test_p_text, key_tmp, N=4)
        if aes_128_tmp.encrypt() == test_c_text:
            ans_key = key
            print(ans_key)

    print(ans_key == [84, 104, 97, 116, 115, 32, 109, 121, 32, 75, 117, 110, 103, 32, 70, 117])


