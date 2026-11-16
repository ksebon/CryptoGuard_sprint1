#include "crypto_guard_ctx.h"
#include <array>
#include <iomanip>
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace CryptoGuard {

using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;

using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })>;

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::Impl {

public:
    Impl() { OpenSSL_add_all_algorithms(); }
    ~Impl() { EVP_cleanup(); }

    Impl(const Impl &) = delete;
    Impl &operator=(const Impl &) = delete;

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        CreateCipher(inStream, outStream, password, 1);
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        CreateCipher(inStream, outStream, password, 0);
    }

    std::string CalculateChecksum(std::iostream &inStream) {
        if (inStream.bad() || (inStream.fail() && !inStream.eof())) {
            throw std::runtime_error{"Input stream is in bad"};
        }

        MdCtxPtr ctx(EVP_MD_CTX_new());
        if (!ctx) {
            throw std::runtime_error{"EVP_MD_CTX_new failed " + PrintOpenSSLError()};
        }

        if (!EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr)) {
            throw std::runtime_error{"EVP_DigestInit_ex failed " + PrintOpenSSLError()};
        }

        std::vector<unsigned char> inBuf(1024);
        std::array<unsigned char, EVP_MAX_MD_SIZE> md_value{};
        unsigned int md_len = 0;

        while (true) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), static_cast<std::streamsize>(inBuf.size()));
            // static_cast<std::streamsize> преобразование unsigned в signed

            if (inStream.bad() || (inStream.fail() && !inStream.eof())) {
                throw std::runtime_error{"read input failed"};
            }

            std::streamsize bytes = inStream.gcount();
            if (bytes == 0) {
                break;
            }

            if (!EVP_DigestUpdate(ctx.get(), inBuf.data(), static_cast<size_t>(bytes))) {
                throw std::runtime_error{"EVP_DigestUpdate failed " + PrintOpenSSLError()};
            }
        }

        if (!EVP_DigestFinal_ex(ctx.get(), md_value.data(), &md_len)) {
            throw std::runtime_error{"EVP_DigestFinal_ex failed " + PrintOpenSSLError()};
        }

        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < md_len; ++i) {
            oss << std::setw(2) << static_cast<int>(md_value[i]);
        }

        return oss.str();
    }

private:
    std::string PrintOpenSSLError() {
        std::string errors;
        unsigned long errCode = 0;
        std::array<char, 256> errBuf{};

        while ((errCode = ERR_get_error()) != 0) {
            ERR_error_string_n(errCode, errBuf.data(), errBuf.size());
            if (!errors.empty()) {
                errors += "; ";
            }
            errors += errBuf.data();
        }

        return errors.empty() ? "unknown OpenSSL error" : errors;
    }

    AesCipherParams CreateCipherParamsFromPassword(std::string_view password, int encrypt) {
        AesCipherParams params;
        params.encrypt = encrypt;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password " + PrintOpenSSLError()};
        }

        return params;
    }

    void CreateCipher(std::iostream &inStream, std::iostream &outStream, std::string_view password, int encrypt) {
        if (password.empty()) {
            throw std::invalid_argument{"Password is empty"};
        }
        if (inStream.bad() || (inStream.fail() && !inStream.eof())) {
            throw std::runtime_error{"Input stream is in bad"};
        }
        if (!outStream.good()) {
            throw std::runtime_error{"Output stream is in bad"};
        }

        auto params = CreateCipherParamsFromPassword(password, encrypt);

        CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) {
            throw std::runtime_error{"EVP_CIPHER_CTX failed " + PrintOpenSSLError()};
        }

        // Инициализируем cipher
        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                               params.encrypt)) {
            throw std::runtime_error{"EVP_CipherInit_ex failed " + PrintOpenSSLError()};
        }

        std::vector<unsigned char> inBuf(1024);
        std::vector<unsigned char> outBuf(inBuf.size() + EVP_MAX_BLOCK_LENGTH);
        int outLen;

        // Обрабатываем
        while (true) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), static_cast<std::streamsize>(inBuf.size()));
            // reinterpret_cast посмотрела в ИИ
            //  inStream.read((char *)inBuf.data(), inBuf.size());
            if (inStream.bad() || (inStream.fail() && !inStream.eof())) {
                throw std::runtime_error{"Read input failed"};
            }

            std::streamsize bytesRead = inStream.gcount();

            if (bytesRead == 0) {
                break;
            }

            if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(bytesRead))) {
                throw std::runtime_error{"EVP_CipherUpdate failed " + PrintOpenSSLError()};
            }

            if (outLen > 0) {
                outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
                if (!outStream) {
                    throw std::runtime_error{"Write to output stream failed"};
                }
            }
        }

        // Заканчиваем работу с cipher
        if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
            throw std::runtime_error{"EVP_CipherFinal_ex failed " + PrintOpenSSLError()};
        }

        if (outLen > 0) {
            outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
            if (!outStream) {
                throw std::runtime_error{"Result write to output stream failed"};
            }
        }

        outStream.flush();
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
