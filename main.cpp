#include <string>

#include "sm4.hpp"

// 根据bitset输出ascii字符串
void outputCode(bitset<128> code) {
    unsigned char ch;
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 8; j++) {
            ch <<= 1;
            ch |= code[127 - i * 8 - j];    // bitset[0]在最右面
        }
        cout << ch;
    }
    cout << endl;
}

int main(int argc, char const* argv[]) {
    string K = "", M = "";
    bitset<128> key = 0x0;
    bitset<128> plain = 0x0;
    bitset<128> cipher = 0x0;
    // 16字符 = 16 * 8位 = 128位
    cout << "输入密钥(16个字符):" << endl;
    cin >> K;
    cout << "输入明文(16个字符):" << endl;
    cin >> M;
    for (int i = 0; i < 16; i++) {
        key <<= 8;
        key |= K[i];
        plain <<= 8;
        plain |= M[i];
    }
    SM4 sm4 = SM4(key);

    cipher = sm4.enc(plain);
    cout << "密文:" << endl;
    outputCode(cipher);

    plain = sm4.dec(cipher);
    cout << "明文:" << endl;
    outputCode(plain);
    return 0;
}
