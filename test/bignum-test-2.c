#include "common/bignum.h"
#include "rand/ctr_drbg.h"
#include "rand/rngw32.h"

#include <stdio.h>

int main() {
    BIGNUM X, A, B;
    char str[2048];
    int n = sizeof(str);

    bn_init(&A, &B, &X, NULL);

    assert(0 == bn_read_string(16, "22612a0d4cb6d1ae162b0ddd6f3c7331"
                                   "7a445a98518b30b2a29ff1e18d635ddb"
                                   "7e6c4a91ecb0f7126faa2a91eb2cb4ef"
                                   "60929467040fa82221724d37b97af5a8"
                                   "e7202f15767e9393ff665bd4188eac9e"
                                   "9379269307052ce58a43626da76ccba3"
                                   "ce8383cbaafaacd878f94ec8702ff8c9"
                                   "f65ffe75773b6439c989b9360a1a2ee4", &A));

    assert(0 == bn_read_string(16, "6765cdb8debf92423588e3aa9ea89c9b"
                                   "d136fde8640ab7b3812cc7d41e74b5b1"
                                   "d9a91e6d9d71da4c0f76fad670e63475"
                                   "515fd7a8c6482b8ec1f90d343eca2faf"
                                   "6b6bae96f69d3a7738c484b9a96a25a8"
                                   "3eb1c618ec7ab30b21a043488f89ee61"
                                   "1257c2eb707fd167dab26e0fc5d4f98f"
                                   "a61653db4f362e6a46cbb0cb3fc052c6", &B));

                                // ans =
                                //    "de2c3e19389af158494e1c0960ea53cc"
                                //    "71e2e879e3b1635a185a2d96459e0117"
                                //    "8d1b47ee7a5e400fcd97c0c746618086"
                                //    "105bde4424bbbdde4ef4c14e3d1ff6e9"
                                //    "3219fec19a2227098e35cdcc3fced51d"
                                //    "81c62eea9cb0eec03a8ba20fe6d90664"
                                //    "3f7f9ecef723c65186b144edc9e1d806"
                                //    "799eb91e122116df8d8dc68f60ae24f4"
                                //    "be822d4133fbafde7dffd73e0eee8cf1"
                                //    "42ed5464585df396d84dc5a63793c54b"
                                //    "2814723c1a3ca0cbf531cac0007dd3aa"
                                //    "011095e5dca122331cf09497041cc3c7"
                                //    "05f2c7acab8f8ad34485110c17abd838"
                                //    "ea95d41d07c7b4d3a6cffa48995d212d"
                                //    "d9bcbfeed6f5adae96920c41ecc8139a"
                                //    "824cbb7e97ea5e8bca883017a454c58"

    assert(0 == bn_mul(&A, &B, &X));

    memset(str, 0, n);
    assert(0 == bn_write_string(16, str, &n, &X));
    fputs(str, stdout);

    bn_init(&A, &B, &X, NULL);

    return 0;
}