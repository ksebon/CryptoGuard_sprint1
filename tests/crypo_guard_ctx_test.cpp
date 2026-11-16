#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>

// TEST(TestComponentName, SimpleCheck) { EXPECT_EQ(1 + 1, 2); }
// TEST for Encrypt
TEST(CryptoGuardCtx, EncryptValid) {
    CryptoGuard::CryptoGuardCtx ctx;
    const std::string text = "Test valid Encrypt";
    std::stringstream inStream(text);
    std::stringstream outStream;

    ASSERT_NO_THROW(ctx.EncryptFile(inStream, outStream, "12345"));

    const std::string encrypted = outStream.str();
    EXPECT_FALSE(encrypted.empty());
    EXPECT_NE(encrypted, text);
}

TEST(CryptoGuardCtx, EncryptsEmpty) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStream("");
    std::stringstream outStream;

    ASSERT_NO_THROW(ctx.EncryptFile(inStream, outStream, "12345"));

    const std::string encrypted = outStream.str();
    EXPECT_EQ(encrypted.size(), 16);
}

TEST(CryptoGuardCtx, EncryptBadData) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream inStream("data");
    std::stringstream outStream;

    // Пустой пароль
    ASSERT_THROW(ctx.EncryptFile(inStream, outStream, ""), std::invalid_argument);

    // Испорченный выходной поток
    std::stringstream validInStream("Test bad data");
    std::stringstream badOutStream;
    badOutStream.setstate(std::ios::failbit);
    ASSERT_THROW(ctx.EncryptFile(validInStream, badOutStream, "password"), std::runtime_error);
}

// TEST for Decrypt
TEST(CryptoGuardCtx, DecryptValid) {
    CryptoGuard::CryptoGuardCtx ctx;
    const std::string text = "Test valid Decrypt";
    const std::string password = "12345";

    std::stringstream inStream(text);
    std::stringstream encrypted;
    ASSERT_NO_THROW(ctx.EncryptFile(inStream, encrypted, password));

    std::stringstream decrypted;
    ASSERT_NO_THROW(ctx.DecryptFile(encrypted, decrypted, password));

    EXPECT_EQ(decrypted.str(), text);
}

TEST(CryptoGuardCtx, DecryptNoValid) {
    CryptoGuard::CryptoGuardCtx ctx;
    const std::string password = "12345";

    std::stringstream decrypted;
    std::stringstream badStream("bad text");
    ASSERT_THROW(ctx.DecryptFile(badStream, decrypted, password), std::runtime_error);

    EXPECT_TRUE(decrypted.str().empty());
}

TEST(CryptoGuardCtx, DecryptBadData) {
    CryptoGuard::CryptoGuardCtx ctx;
    const std::string text = "Test bad data";
    const std::string password = "12345";

    std::stringstream inStream(text);
    std::stringstream encrypted;
    ASSERT_NO_THROW(ctx.EncryptFile(inStream, encrypted, password));
    const std::string encryptedData = encrypted.str();

    std::stringstream decrypted;
    // без пароля
    ASSERT_THROW(ctx.DecryptFile(encrypted, decrypted, ""), std::invalid_argument);

    // Неверный пароль
    ASSERT_THROW(ctx.DecryptFile(encrypted, decrypted, "54321"), std::runtime_error);

    std::stringstream failStream(encryptedData);
    failStream.setstate(std::ios::failbit);
    ASSERT_THROW(ctx.DecryptFile(failStream, decrypted, password), std::runtime_error);
}

// TEST for CalculateChecksum
TEST(CryptoGuardCtx, ChecksumEmpty) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream ss;
    EXPECT_EQ(ctx.CalculateChecksum(ss), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(CryptoGuardCtx, ChecksumText) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream ss("Hello World");
    EXPECT_EQ(ctx.CalculateChecksum(ss), "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e");
}
