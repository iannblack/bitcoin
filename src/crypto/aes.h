// Copyright (c) 2015-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// C++ wrapper around ctaes, a constant-time AES implementation

#ifndef BITCOIN_CRYPTO_AES_H
#define BITCOIN_CRYPTO_AES_H

extern "C" {
#include <crypto/ctaes/ctaes.h>
}

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

constexpr int AES_BLOCKSIZE = 16;
constexpr int AES256_KEYSIZE = 32;

/** An encryption class for AES-256. */
class AES256Encrypt
{
private:
    AES256_ctx ctx;

public:
    explicit AES256Encrypt(const std::array<uint8_t, AES256_KEYSIZE>& key);
    ~AES256Encrypt();
    void Encrypt(std::array<uint8_t, AES_BLOCKSIZE>& ciphertext, const std::array<uint8_t, AES_BLOCKSIZE>& plaintext) const;
};

/** A decryption class for AES-256. */
class AES256Decrypt
{
private:
    AES256_ctx ctx;

public:
    explicit AES256Decrypt(const std::array<uint8_t, AES256_KEYSIZE>& key);
    ~AES256Decrypt();
    void Decrypt(std::array<uint8_t, AES_BLOCKSIZE>& plaintext, const std::array<uint8_t, AES_BLOCKSIZE>& ciphertext) const;
};

/** AES-256 CBC encryption with optional padding. */
class AES256CBCEncrypt
{
public:
    AES256CBCEncrypt(const std::array<uint8_t, AES256_KEYSIZE>& key, const std::array<uint8_t, AES_BLOCKSIZE>& ivIn, bool padIn = true);
    ~AES256CBCEncrypt();
    int Encrypt(const uint8_t* data, size_t size, uint8_t* out) const;

private:
    const AES256Encrypt enc;
    const bool pad;
    std::array<uint8_t, AES_BLOCKSIZE> iv;
};

/** AES-256 CBC decryption with optional padding. */
class AES256CBCDecrypt
{
public:
    AES256CBCDecrypt(const std::array<uint8_t, AES256_KEYSIZE>& key, const std::array<uint8_t, AES_BLOCKSIZE>& ivIn, bool padIn = true);
    ~AES256CBCDecrypt();
    int Decrypt(const uint8_t* data, size_t size, uint8_t* out) const;

private:
    const AES256Decrypt dec;
    const bool pad;
    std::array<uint8_t, AES_BLOCKSIZE> iv;
};

#endif // BITCOIN_CRYPTO_AES_H
