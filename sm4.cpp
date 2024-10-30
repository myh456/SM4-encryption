#include "sm4.hpp"

// n位bitset数循环左移pos位(没有越界检查)
#define LLL(bs, pos, n)  (bs) << (pos) | (bs) >> (n - pos)
// 提取bitset<8>前4位
#define FRONT4(bs) (bs).to_ulong() >> 4
// 提取bitset<8>后4位
#define END4(bs) (bs).to_ulong() & 0xf

// 连接4个bitset
template<size_t N>
bitset<4 * N> combine(const bitset<N> bs1, const bitset<N> bs2, const bitset<N> bs3, const bitset<N> bs4) {
    bitset<4 * N> result;
    for (int i = 0; i < N; i++) {
        result[i] = bs1[i];
        result[i + N] = bs2[i];
        result[i + 2 * N] = bs3[i];
        result[i + 3 * N] = bs4[i];
    }
    return result;
}

bitset<32> SM4::funcT(bitset<32> B) {
    vector<bitset<8>> b = vector<bitset<8>>(4, 0x0);
    // 把32位的B分成4 * 8位的b[4]
    for (int i = 0; i < 32; i++) {
        b[i / 8][i % 8] = B[i];
    }
    // S盒变换
    vector<bitset<8>> a = vector<bitset<8>>(4, 0x0);
    for (int i = 0; i < 4; i++) {
        a[i] = this->SBox[FRONT4(b[i])][END4(b[i])];
    }
    bitset<32> A = bitset<32>(combine(a[0], a[1], a[2], a[3]));
    // 线性变换
    return A ^ LLL(A, 13, 32) ^ LLL(A, 23, 32);
}

bitset<32> SM4::funcTp(bitset<32> B) {
    vector<bitset<8>> b = vector<bitset<8>>(4, 0x0);
    // 把32位的B分成4 * 8位的b[4]
    for (int i = 0; i < 32; i++) {
        b[i / 8][i % 8] = B[i];
    }
    // S盒变换
    vector<bitset<8>> a = vector<bitset<8>>(4, 0x0);
    for (int i = 0; i < 4; i++) {
        a[i] = this->SBox[FRONT4(b[i])][END4(b[i])];
    }
    bitset<32> A = bitset<32>(combine(a[0], a[1], a[2], a[3]));
    // 线性变换
    return A ^ LLL(A, 2, 32) ^ LLL(A, 10, 32) ^ LLL(A, 18, 32) ^ LLL(A, 24, 32);
}

void SM4::subkey(bitset<128> key) {
    vector<bitset<32>> MKi = vector<bitset<32>>(4, 0x0);
    // 拆分
    for (int i = 0; i < 128; i++) {
        MKi[i / 32][i % 32] = key[i];
    }
    // 初始化
    vector<bitset<32>> Ki = vector<bitset<32>>(36, 0x0);
    for (int i = 0; i < 4; i++) {
        Ki[i] = MKi[i] ^ this->FKi[i];
    }
    // 32轮迭代
    for (int i = 0; i < 32; i++) {
        this->rki[i] = Ki[i + 4] = Ki[i] ^ funcT(Ki[i + 1] ^ Ki[i + 2] ^ Ki[i + 3] ^ this->CKi[i]);
    }
}

bitset<128> SM4::enc(bitset<128> M) {
    vector<bitset<32>> Xi = vector<bitset<32>>(36, 0x0);
    bitset<128> result = 0x0;
    // 拆分
    for (int i = 0; i < 128; i++) {
        Xi[i / 32][i % 32] = M[i];
    }
    // 32轮迭代
    for (int i = 0; i < 32; i++) {
        Xi[i + 4] = Xi[i] ^ funcTp(Xi[i + 1] ^ Xi[i + 2] ^ Xi[i + 3] ^ this->rki[i]);
    }
    // 反序变换
    result = bitset<128>(combine(Xi[35], Xi[34], Xi[33], Xi[32]));
    return result;
}

bitset<128> SM4::dec(bitset<128> C) {
    // 反序使用轮密钥
    bitset<128> result;
    reverse(this->rki.begin(), this->rki.end());
    result = this->enc(C);
    reverse(this->rki.begin(), this->rki.end());
    return result;
}

SM4::SM4() { }
SM4::SM4(bitset<128> key) {
    this->subkey(key);
}