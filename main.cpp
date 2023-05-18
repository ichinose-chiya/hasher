#include <cstdio>
#include <iostream>
#include <cstdint>
#include <cstring>
#include <string>
#include <cstdint>
#include <iomanip>

#include "md5.h"

using namespace std;

static void hex_dump(const uint8_t *src, size_t src_len)
{
    for (int i = 0; i < src_len; i++) {
        cout << hex << setfill('0') << setw(2) << (int) src[i];
    }
}

int main(int argc, char*argv[], char*envp[])
{
    myhash::hasher *hasher;
    string algo;
    uint8_t *src, *res;
    size_t src_len, res_len;

    if (argc < 3) {
        cout << "[*] Usage: ./hasher {algorithm} {string_to_hash}" << endl;
        cout << "    Redundant arguments will be ignored." << endl;
        return 0;
    }

    algo = argv[1];
    for (int i = 0; i < algo.size(); i++) {
        algo[i] = toupper(algo.c_str()[i]);
    }

    src = (uint8_t*) argv[2]; 
    src_len = strlen(argv[2]);

    cout << "[*] Original string: ";
    hex_dump(src, src_len);
    cout << endl;
    cout << "[*] Algorithm: " << algo << endl;

    if (algo == "MD5") {
        res = new uint8_t[16];
        res_len = 16;
        hasher = new myhash::md5_hasher;
        hasher->hash(src, src_len, res);
    } else {
        cerr << "[x] Unsupported algorithm: " << algo << endl;
        return 0;
    }

    cout << "[+] The result is: ";
    hex_dump(res, res_len);
    cout << endl;

    return 0;
}