#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>

using namespace CryptoGuard;

// Test fixture for CryptoGuardCtx encryption tests
class CryptoGuardCtxEncryptTest : public ::testing::Test {
protected:
    CryptoGuardCtx cryptoCtx;
    const std::string testPassword = "testPassword123";
};

// Test 1: Basic encryption of simple text
TEST_F(CryptoGuardCtxEncryptTest, EncryptSimpleText) {
    std::stringstream inStream;
    std::stringstream outStream;

    inStream << "Hello, World!";
    inStream.seekg(0);

    EXPECT_NO_THROW(cryptoCtx.EncryptFile(inStream, outStream, testPassword));

    // Verify that output is not empty
    outStream.seekg(0);
    std::string encryptedData;
    std::getline(outStream, encryptedData);
    EXPECT_FALSE(encryptedData.empty());

    // Verify that encrypted data is different from original
    EXPECT_NE(encryptedData, "Hello, World!");
}

// Test 2: Encryption of longer text (multiple buffer chunks)
TEST_F(CryptoGuardCtxEncryptTest, EncryptLargeText) {
    std::stringstream inStream;
    std::stringstream outStream;

    // Create text larger than buffer size (>1024 bytes)
    std::string largeText(2048, 'A');
    inStream << largeText;
    inStream.seekg(0);

    EXPECT_NO_THROW(cryptoCtx.EncryptFile(inStream, outStream, testPassword));

    // Verify that output contains encrypted data
    std::string encryptedData;
    outStream.seekg(0, std::ios::end);
    size_t size = outStream.tellg();
    EXPECT_GT(size, 0);
}

// Test 3: Encryption with bad input stream should throw
TEST_F(CryptoGuardCtxEncryptTest, EncryptWithBadInputStreamThrows) {
    std::stringstream inStream;
    std::stringstream outStream;

    // Set input stream to a bad state
    inStream.setstate(std::ios::badbit);

    EXPECT_THROW(cryptoCtx.EncryptFile(inStream, outStream, testPassword), std::runtime_error);
}

// Test 4: Encryption with bad output stream should throw
TEST_F(CryptoGuardCtxEncryptTest, EncryptWithBadOutputStreamThrows) {
    std::stringstream inStream;
    std::stringstream outStream;

    inStream << "test data";
    inStream.seekg(0);

    // Set output stream to a bad state
    outStream.setstate(std::ios::badbit);

    EXPECT_THROW(cryptoCtx.EncryptFile(inStream, outStream, testPassword), std::runtime_error);
}

// Test 5: Encryption with empty password
TEST_F(CryptoGuardCtxEncryptTest, EncryptWithEmptyPasswordSucceeds) {
    std::stringstream inStream;
    std::stringstream outStream;

    inStream << "Data with empty password";
    inStream.seekg(0);

    // Empty password should still work (though not secure)
    EXPECT_NO_THROW(cryptoCtx.EncryptFile(inStream, outStream, ""));

    // Verify encryption occurred
    outStream.seekg(0, std::ios::end);
    size_t size = outStream.tellg();
    EXPECT_GT(size, 0);
}

// Test 6: Encryption with empty input (edge case)
TEST_F(CryptoGuardCtxEncryptTest, EncryptEmptyInputSucceeds) {
    std::stringstream inStream;
    std::stringstream outStream;

    // Input is empty
    inStream.seekg(0);

    EXPECT_NO_THROW(cryptoCtx.EncryptFile(inStream, outStream, testPassword));

    // Output should have at least the padding from EVP_CipherFinal_ex
    outStream.seekg(0, std::ios::end);
    size_t size = outStream.tellg();
    EXPECT_GT(size, 0);
}
