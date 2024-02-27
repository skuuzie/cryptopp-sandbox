#include "util.h"

#include "base64.h"
#include "files.h"
#include "filters.h"
#include "gcm.h"
#include "hex.h"
#include "modes.h"
#include "osrng.h"
#include "rijndael.h"
#include "rng.h"

void generateRandomBytes(CryptoPP::SecByteBlock* out, size_t size) {
	if (out->size() < size) {
		std::cerr << "generateRandomBytes error: output buffer is smaller than demanded size." << std::endl;
		exit(1);
	}

	CryptoPP::OS_GenerateRandomBlock(false, out->data(), size);
}

void hexlify(const CryptoPP::byte* buffer, const size_t length, std::string& encoded) {
	CryptoPP::HexEncoder encoder;

	encoder.Put(buffer, length);
	encoder.MessageEnd();

	auto size = encoder.MaxRetrievable();

	if (size) {
		encoded.resize(size);
		encoder.Get((CryptoPP::byte*) &encoded[0], encoded.size());
	}
}

void unhex(const std::string& hex, const size_t length, CryptoPP::SecByteBlock* decoded) {
	CryptoPP::HexDecoder decoder;

	decoder.Put((CryptoPP::byte*) hex.data(), length);
	decoder.MessageEnd();

	auto size = decoder.MaxRetrievable();

	if (size) {
		decoded->resize(size);
		decoder.Get(decoded->data(), decoded->size());
	}
}

void encryptAesCbc(const CryptoPP::byte* in, const size_t in_length, CryptoPP::SecByteBlock* out) {
	CryptoPP::SecByteBlock key(32);
	CryptoPP::SecByteBlock iv(16);

	CryptoPP::memset_z(key, 0xde, 32);
	CryptoPP::memset_z(iv, 0xad, 16);

	try 
	{
		CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		if (in_length % 16 == 0) {
			out->resize(in_length); // no padding needed

			CryptoPP::StringSource s(in, in_length, true,
				new CryptoPP::StreamTransformationFilter(
					e,
					new CryptoPP::ArraySink(*out, out->size()),
					CryptoPP::BlockPaddingSchemeDef::NO_PADDING
				)
			);
		}
		else {
			out->resize(CryptoPP::AES::BLOCKSIZE * (ceil((float)in_length / 16))); // resize output buffer to padded size

			CryptoPP::StringSource s(in, in_length, true,
				new CryptoPP::StreamTransformationFilter(
					e,
					new CryptoPP::ArraySink(*out, out->size()),
					CryptoPP::BlockPaddingSchemeDef::DEFAULT_PADDING
				)
			);
		}
	}
	catch (const CryptoPP::Exception& e) 
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}
}

void decryptAesCbc(const CryptoPP::byte* in, const size_t in_length, CryptoPP::SecByteBlock* out) {
	CryptoPP::SecByteBlock key(32);
	CryptoPP::SecByteBlock iv(16);

	CryptoPP::memset_z(key, 0xde, 32);
	CryptoPP::memset_z(iv, 0xad, 16);

	try
	{
		CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		std::string str;

		CryptoPP::StringSource s(in, in_length, true,
			new CryptoPP::StreamTransformationFilter(
				d,
				new CryptoPP::StringSink(str), // usage of arraysink isn't possible because of the unknown original plaintext length
				CryptoPP::BlockPaddingSchemeDef::DEFAULT_PADDING
			)
		);
		
		// not ideal, but using filters is the simplest and fastest way possible
		out->resize(str.size());
		std::copy(str.begin(), str.end(), out->begin());

		/*

			Using ArraySink with manual unpadding is a good alternative.

			StreamTransformationFilter does have automatic unpadding mechanism.
			But using ArraySource/ArraySink needs a fixed size buffer and we don't know the original msg length, 
			so we need to manually unpad and resize the output buffer.

			Note: PKCS padding only.
		

		const unsigned int PAD_SIZE = out->data()[out->size() - 1];

		unsigned int counter = 0;

		for (int i = out->size() - 1; i >= 0; i--) {

			if (((unsigned int) out->data()[i] == PAD_SIZE) && (counter != PAD_SIZE)) {
				counter++;
			}
			else if (counter == PAD_SIZE) {
				const size_t original_size = in_length - PAD_SIZE;
				out->resize(original_size);
			}
			else {
				return;
			}

		}

		*/
	}
	catch (const CryptoPP::Exception& e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}
}

void encryptAesGcm(const CryptoPP::byte* in, const size_t in_length, const unsigned int tag_size, CryptoPP::SecByteBlock* out) {

	CryptoPP::SecByteBlock key(32);
	CryptoPP::SecByteBlock iv(16);

	CryptoPP::memset_z(key, 0xde, 32);
	CryptoPP::memset_z(iv, 0xad, 16);

	try
	{
		out->resize(in_length + tag_size);

		CryptoPP::GCM<CryptoPP::AES>::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		std::string str;

		CryptoPP::StringSource s(in, in_length, true,
			new CryptoPP::AuthenticatedEncryptionFilter(
				e,
				new CryptoPP::ArraySink(out->data(), out->size()),
				false, // putAAD
				tag_size
			)
		);
	}
	catch (CryptoPP::Exception& e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}
}

void decryptAesGcm(const CryptoPP::byte* in, const size_t in_length, const unsigned int tag_size, CryptoPP::SecByteBlock* out) {
	CryptoPP::SecByteBlock key(32);
	CryptoPP::SecByteBlock iv(16);

	CryptoPP::memset_z(key, 0xde, 32);
	CryptoPP::memset_z(iv, 0xad, 16);

	try
	{
		out->resize(in_length - tag_size);

		CryptoPP::GCM<CryptoPP::AES>::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		CryptoPP::AuthenticatedDecryptionFilter df(
			d,
			new CryptoPP::ArraySink(out->data(), out->size()),
			16U, // DEFAULT_FLAGS
			tag_size
		);

		df.Put(in, in_length);
		df.MessageEnd();

		if (true == df.GetLastResult()) {
			// std::cout << "Ok" << std::endl;	
		}

	}
	catch (CryptoPP::Exception& e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}
}

void createRsaKey(const std::string& filename, const unsigned int size) {
	std::cout << std::endl;

	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::InvertibleRSAFunction params;

	CryptoPP::ByteQueue queue;

	params.GenerateRandomWithKeySize(rng, size);
	params.Save(queue);

	saveBufferedTransformation(filename, queue);

	/* HEX ENCODING */
	CryptoPP::HexEncoder encoder;
	std::string encoded_key;

	queue.CopyTo(encoder);
	encoder.MessageEnd();

	auto encoded_size = encoder.MaxRetrievable();
	if (encoded_size) {
		encoded_key.resize(encoded_size);
		encoder.Get((CryptoPP::byte*)&encoded_key[0], encoded_key.size());
	}
	/* HEX ENCODING */

	std::cout << "Created RSA key to: " << filename << std::endl;
	std::cout << "Hex-encoded: " << encoded_key << std::endl;
}

void loadRsaKeyFromFile(const std::string& filename, CryptoPP::InvertibleRSAFunction* params) {
	std::cout << std::endl;

	try
	{
		CryptoPP::ByteQueue bt;
		CryptoPP::FileSource file(filename.c_str(), true);

		file.TransferTo(bt);
		bt.MessageEnd();

		params->Load(bt);

		std::cout << "RSA key loaded successfully." << std::endl;
	}
	catch (const CryptoPP::Exception& e)
	{
		std::cerr << std::endl << "loadRsaKey error: " << e.what() << std::endl;
		exit(1);
	}
}

void saveBufferedTransformation(const std::string& filename, const CryptoPP::BufferedTransformation& bt) {
	CryptoPP::FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}

void encryptRsa(const CryptoPP::InvertibleRSAFunction params, const CryptoPP::byte* in, const size_t in_length, CryptoPP::SecByteBlock* out) {
	CryptoPP::AutoSeededRandomPool rng;

	CryptoPP::RSA::PublicKey publicKey(params);
	CryptoPP::RSAES_OAEP_SHA256_Encryptor e(publicKey);

	std::string enc;

	try
	{
		CryptoPP::StringSource s(
			in,
			in_length,
			true,
			new CryptoPP::PK_EncryptorFilter(
				rng,
				e,
				new CryptoPP::StringSink(enc)
			)
		);
	}
	catch (const CryptoPP::Exception& e)
	{
		std::cerr << std::endl << "encryptRsa error: " << e.what() << std::endl;
		exit(1);
	}

	// not ideal, but using filters is the simplest and fastest way possible
	out->resize(enc.size());
	std::copy(enc.begin(), enc.end(), out->begin());
}

void decryptRsa(const CryptoPP::InvertibleRSAFunction params, const CryptoPP::byte* in, const size_t in_length, CryptoPP::SecByteBlock* out) {
	CryptoPP::AutoSeededRandomPool rng;

	CryptoPP::RSA::PrivateKey privateKey(params);
	CryptoPP::RSAES_OAEP_SHA256_Decryptor d(privateKey);

	std::string dec;

	try
	{
		CryptoPP::StringSource s(
			in,
			in_length,
			true,
			new CryptoPP::PK_DecryptorFilter(
				rng,
				d,
				new CryptoPP::StringSink(dec)
			)
		);
	}
	catch (const CryptoPP::Exception& e)
	{
		std::cerr << std::endl << "decryptRsa error: " << e.what() << std::endl;
		exit(1);
	}

	// not ideal, but using filters is the simplest and fastest way possible
	out->resize(dec.size());
	std::copy(dec.begin(), dec.end(), out->begin());
}