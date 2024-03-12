# Xrand

C library for cryptographically secure random number generation.

 [![Static Badge](https://img.shields.io/badge/license-GPL%20v3.0-orange?style=plastic&logo=gnu&color=D76764)](https://github.com/vibhav950/Xrand/blob/main/LICENSE) ![Static Badge](https://img.shields.io/badge/version-1.0.1--alpha-blue?style=plastic) [![Static Badge](https://img.shields.io/badge/docs-here-purple?style=plastic&color=8A2BE2)](https://vibhav950.github.io/Xrand/) ![Static Badge](https://img.shields.io/badge/tests-pending-red?style=plastic&color=FF2400)

## Features

* Generation of random data with high security strength - the randomness pool maintains a high entropy reserve for all key, nonce, salt, IV, and token generation purposes.
* High statistical correlation with observations of ideal random bitstrings and built-in measures to prevent the possibility of computing predecessors upon knowledge of an output subsequence.
* Fast SP 800-90A DRBG for generating large volumes of random data for uses like wiping disk sectors before encryption and SSL/TLS key generation on high-traffic servers.
* Not reliant on user interaction for gathering randomness, making it suitable for use on unattended systems acting as network nodes or servers.

## Compatibility State

As of `v1.0.1-alpha`, Xrand is only compatible with `Win32` systems.

## System Requirements

This library requires OpenSSL 3.0 for cryptographic functionality. To build OpenSSL on Windows, see the [Notes for Windows platforms](https://github.com/openssl/openssl/blob/master/NOTES-WINDOWS.md) on the [official OpenSSL Git Repository](https://github.com/openssl/openssl/).

For MinGW, you can use the MSYS2 environment to build native OpenSSL through cross-compilation. Install MSYS2 from [here](https://www.msys2.org/) and run the following commands in the shell to build OpenSSL

```bash
pacman -Syu
pacman -S mingw-w64-x86_64-openssl
```

## Usage

You can obtain a local copy of the Git repository to compile the source code and run tests

```powershell
git clone https://github.com/vibhav950/Xrand.git
cd Xrand
make
```

To get random data in your application

```c
#include "rand/rngw32.h"
#include "common/defs.h"

int main(void)
{
    /* Initialize the entropy pool */
    ASSERT(RngStart() == true);

    /* Buffer to hold the random data */
    byte rand_bytes[64];

    /* Fetch bytes from the entropy pool */
    ASSERT(RngFetchBytes(rand_bytes, 64) == true);

    /* Process the bytes */
    /* ... */

    /* Stop the RNG */
    RngStop();

    return 0;
}
```

## Development

If you wish to contribute to Xrand either to fix bugs or contribute new features, you will have to fork this GitHub repository `vibhav950/Xrand` and clone your public fork

```powershell
git clone https://github.com/yourname/Xrand.git
```

This is necessary since all development for this project will be done only via GitHub pull requests. For more details about the contribution policies, see [Contributing](https://github.com/vibhav950/Xrand/blob/main/CONTRIBUTING.md).

## Todo

* [ ] Generation of probable primes based on the Miller-Rabin primality test as defined in the [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) standard.
* [ ] Modes of operation for providing key streams of different strength levels (or randomness "quality") so that the client application can directly instantiate the generator with a preset security strength.
