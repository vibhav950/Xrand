# Xrand

C library for cryptographically secure random number generation.

 [![Static Badge](https://img.shields.io/badge/license-GPL%20v3.0-orange?style=plastic&logo=gnu&color=D76764)](https://github.com/vibhav950/Xrand/blob/main/LICENSE) ![Static Badge](https://img.shields.io/badge/version-1.0.1--alpha-blue?style=plastic) [![Static Badge](https://img.shields.io/badge/docs-here-purple?style=plastic&color=8A2BE2)](https://vibhav950.github.io/Xrand/) ![Static Badge](https://img.shields.io/badge/tests-pending-red?style=plastic&color=FF2400)

## Features

* Generation of random data with high security strength - the randomness pool maintains a high entropy reserve for all key, nonce, salt, IV, and token generation purposes.
* High statistical correlation with observations of ideal random bitstrings and built-in measures to prevent the possibility of computing predecessors upon knowledge of an output subsequence.
* Fast SP 800-90A DRBG for generating large volumes of random data for uses like wiping disk sectors before encryption and SSL/TLS key generation on high-traffic servers.
* Not reliant on user interaction for gathering randomness, making it suitable for use on unattended systems acting as network nodes or servers.

## Compatibility State

Currently only compatible with `Win32` systems.

## How to Use

Clone the repo to your local machine and simply run `make` to check for compilation dependancies.

## How to Contribute

To add relevant features or security fixes to the repo, add your contributions to a fork and I will review your pull request as soon as possible. Please do not submit a feature unrelated to random number generation and its applications.

## Future Prospects and Upcoming Features

Future versions will add/extend support for common security protocols and application-specific features like generation of PKCS keys, prime numbers and cryptographic tokens.
