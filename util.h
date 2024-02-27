#pragma once

#include <iostream>

#include "secblock.h"
#include "rsa.h"

/// @brief OS-based RNG
/// @param out: pointer to store random bytes
/// @param size: size in byte
void generateRandomBytes(CryptoPP::SecByteBlock* out,
                         size_t size);

/// @brief Hex encoding
/// @param buffer: pointer to buffer to be encoded
/// @param length: length of buffer
/// @param encoded: pointer to store the encoded
void hexlify(const CryptoPP::byte* buffer,
             const size_t length,
             std::string& encoded);

/// @brief Hex decoding
/// @param hex: hexstring to be decoded
/// @param length: length of string (lol)
/// @param encoded: pointer to store the decoded
void unhex(const std::string& hex,
           const size_t length,
           CryptoPP::SecByteBlock* decoded);

/// @brief AES-CBC encryption
/// @param in: pointer to input to be encrypted
/// @param in_length: length of input
/// @param out: pointer to store encrypted input
void encryptAesCbc(const CryptoPP::byte* in,
                   const size_t in_length,
                   CryptoPP::SecByteBlock* out);

/// @brief AES-CBC decryption
/// @param in: pointer to input to be decrypted
/// @param in_length: length of input
/// @param out: pointer to store decrypted input
void decryptAesCbc(const CryptoPP::byte* in,
                   const size_t in_length,
                   CryptoPP::SecByteBlock* out);

/// @brief AES-GCM encryption (authenticated without additional data)
/// @param in: pointer to input to be encrypted
/// @param in_length: length of input
/// @param tag_size: mac length - recommended 12 or 16
/// @param out: pointer to store encrypted input
void encryptAesGcm(const CryptoPP::byte* in,
                   const size_t in_length,
                   const unsigned int tag_size,
                   CryptoPP::SecByteBlock* out);

/// @brief AES-GCM decryption (authenticated without additional data)
/// @param in: pointer to input to be decrypted
/// @param in_length: length of input
/// @param tag_size: mac length - recommended 12 or 16
/// @param out: pointer to store decrypted input
void decryptAesGcm(const CryptoPP::byte* in,
                   const size_t in_length,
                   const unsigned int tag_size,
                   CryptoPP::SecByteBlock* out);

/// @brief Create and save RSA key
/// @param filename: to store the key
/// @param size: key size (bit) - recommended 2048
void createRsaKey(const std::string& filename,
                  const unsigned int size);

/// @brief Load RSA key from file
/// @param filename: to fetch the key
/// @param bt: BufferedTransformation to store the key
void loadRsaKeyFromFile(const std::string& filename,
                        CryptoPP::InvertibleRSAFunction* params);

/// @brief Save a BufferedTransformation to file
void saveBufferedTransformation(const std::string& filename,
                                const CryptoPP::BufferedTransformation& bt);

/// @brief RSA encryption
/// @param params: RSA key
/// @param in: pointer to input to be encrypted
/// @param in_length: length of input
/// @param out: pointer to store encrypted input
void encryptRsa(const CryptoPP::InvertibleRSAFunction params,
                const CryptoPP::byte* in,
                const size_t in_length,
                CryptoPP::SecByteBlock* out);

/// @brief RSA decryption
/// @param params: RSA key
/// @param in: pointer to input to be decrypted
/// @param in_length: length of input
/// @param out: pointer to store decrypted input
void decryptRsa(const CryptoPP::InvertibleRSAFunction params,
                const CryptoPP::byte* in,
                const size_t in_length,
                CryptoPP::SecByteBlock* out);