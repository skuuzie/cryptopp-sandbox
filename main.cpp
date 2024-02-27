#include "sha.h"

#include "util.h"

void hashTest(const CryptoPP::byte* in, const size_t in_length);

void aesCbcTest(const CryptoPP::byte* in, const size_t in_length);

void aesGcmTest(const CryptoPP::byte* in, const size_t in_length);

void rsaCryptTest(const CryptoPP::InvertibleRSAFunction params, const CryptoPP::byte* in, const size_t in_length);

void rngTest(size_t size);

int main() {

	rngTest(16);

	// "snowy snow"
	CryptoPP::byte in[10] = { 0x73, 0x6e, 0x6f, 0x77, 0x79, 0x20, 0x73, 0x6e, 0x6f, 0x77 };

	/*
		alternative:
			unhex(some_hexstr, some_hexstr.size(), &some_secbyteblock);
			base64
	*/

	// conversion
	std::string in_str(reinterpret_cast<const char*>(&in[0]), sizeof(in));
	CryptoPP::SecByteBlock in_secbyte(in, sizeof(in));

	// pretty-print input
	std::string plain_encoded;
	hexlify(in, sizeof(in), plain_encoded);

	std::cout << std::endl << "Input: " << plain_encoded << " | " << in_str << std::endl;

	// hashing, and symmetric encryption
	hashTest(in, sizeof(in));
	aesCbcTest((const CryptoPP::byte*) in_str.data(), in_str.size());
	aesGcmTest((const CryptoPP::byte*) in_secbyte.data(), in_secbyte.size());

	// asymmetric encryption
	CryptoPP::InvertibleRSAFunction params;

	createRsaKey("test.rsa", 2048);
	loadRsaKeyFromFile("test.rsa", &params);
	rsaCryptTest(params, in, sizeof(in));
}

void rngTest(size_t size) {
	std::cout << std::endl;

	CryptoPP::SecByteBlock rng(size);
	std::string encoded;

	for (int i = 0; i < 15; i++) {
		generateRandomBytes(&rng, rng.size());

		hexlify(rng.data(), rng.size(), encoded);

		std::cout << "RNG: " << encoded << std::endl;

		rng.CleanNew(size);
		encoded.clear();
	}
}

void hashTest(const CryptoPP::byte* in, const size_t in_length) {
	std::cout << std::endl;

	CryptoPP::SHA256 hash;
	CryptoPP::byte buf[hash.DIGESTSIZE];

	std::string input;
	std::string hashed;

	/*
	   hash.Update(in, in_length);
	   hash.Final(buf);
	*/

	hash.CalculateDigest(buf, in, in_length);

	hexlify(in, in_length, input);
	hexlify(buf, hash.DIGESTSIZE, hashed);

	// Manual assertion for "snowy snow"
	if (strcmp(hashed.data(), "8E3426A13CF5A286200B71A32C0DC428D2CA48C65C70628EF71F27C2F294C395") != 0) {
		std::cerr << "Error: Hash (" << hash.AlgorithmName() << ") assertion failure." << std::endl;
		exit(1);
	}

	std::cout << hash.AlgorithmName() << std::endl;
	std::cout << "Result: " << hashed << std::endl;
}

void aesCbcTest(const CryptoPP::byte* in, const size_t in_length) {
	std::cout << std::endl;

	std::string enc_encoded;
	std::string dec_encoded;

	// Encryption
	CryptoPP::SecByteBlock enc;
	encryptAesCbc(in, in_length, &enc);

	// Decryption
	CryptoPP::SecByteBlock dec;
	decryptAesCbc(enc.data(), enc.size(), &dec);

	// Assertion
	if (!CryptoPP::VerifyBufsEqual(in, dec.data(), in_length)) {
		std::cerr << "Error: AES-CBC assertion failure." << std::endl;
		exit(1);
	}

	// Hex encrypted and decrypted
	hexlify(enc, enc.size(), enc_encoded);
	hexlify(dec, dec.size(), dec_encoded);

	// Print
	std::cout << "AES-CBC" << std::endl;
	std::cout << "Ciphertext: " << enc_encoded << std::endl;
	std::cout << "Decrypted: " << dec_encoded << " | " << std::string(reinterpret_cast<const char*>(&dec[0]), dec.size()) << std::endl;
}

void aesGcmTest(const CryptoPP::byte* in, const size_t in_length) {
	std::cout << std::endl;

	// Encryption
	CryptoPP::SecByteBlock enc;
	encryptAesGcm(in, in_length, 12, &enc);

	// Decryption
	CryptoPP::SecByteBlock dec;
	decryptAesGcm(enc.data(), enc.size(), 12, &dec);

	// Hex encrypted and decrypted
	std::string enc_encoded, dec_encoded;
	hexlify(enc.data(), enc.size(), enc_encoded);
	hexlify(dec.data(), dec.size(), dec_encoded);

	// Print
	std::cout << "AES-GCM (Authenticated Encryption without Additional Data)" << std::endl;
	std::cout << "Ciphertext: " << enc_encoded << std::endl;
	std::cout << "Decrypted: " << dec_encoded << " | " << std::string(reinterpret_cast<const char*>(&dec[0]), dec.size()) << std::endl;
}

void rsaCryptTest(const CryptoPP::InvertibleRSAFunction params, const CryptoPP::byte* in, const size_t in_length) {
	std::cout << std::endl;

	// Encryption
	CryptoPP::SecByteBlock enc;
	encryptRsa(params, in, in_length, &enc);

	// Decryption
	CryptoPP::SecByteBlock dec;
	decryptRsa(params, enc.data(), enc.size(), &dec);

	// Hex encrypted and decrypted
	std::string enc_encoded, dec_encoded;
	hexlify(enc.data(), enc.size(), enc_encoded);
	hexlify(dec.data(), dec.size(), dec_encoded);

	// Print
	std::cout << "RSA-OAEP (with SHA-256)" << std::endl;
	std::cout << "Ciphertext: " << enc_encoded << std::endl;
	std::cout << "Decrypted: " << dec_encoded << " | " << std::string(reinterpret_cast<const char*>(&dec[0]), dec.size()) << std::endl;
}