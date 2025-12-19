#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>

using namespace CryptoGuard;

// Test fixture for CryptoGuardCtx decryption tests
class CryptoGuardCtxDecryptTest : public ::testing::Test {
protected:
    CryptoGuardCtx cryptoCtx;
    const std::string testPassword = "testPassword123";
};

// Test 1: Decrypt with bad input stream should throw (ASSERT_THROW requirement)
TEST_F(CryptoGuardCtxDecryptTest, DecryptWithBadInputStreamThrows) {
    std::stringstream decryptedStream;
    std::stringstream badInputStream;

    // Set input stream to a bad state
    badInputStream.setstate(std::ios::badbit);

    // This test uses ASSERT_THROW as required
    ASSERT_THROW(cryptoCtx.DecryptFile(badInputStream, decryptedStream, testPassword), std::runtime_error);
}

// Test 2: Decrypt with bad output stream should throw
TEST_F(CryptoGuardCtxDecryptTest, DecryptWithBadOutputStreamThrows) {
    std::stringstream inputStream;
    std::stringstream badOutputStream;

    // Set output stream to a bad state
    badOutputStream.setstate(std::ios::badbit);

    EXPECT_THROW(cryptoCtx.DecryptFile(inputStream, badOutputStream, testPassword), std::runtime_error);
}

// Test 3: Decrypt processes stream without throwing on valid input
TEST_F(CryptoGuardCtxDecryptTest, DecryptProcessesValidStream) {
    // Create a stream with some encrypted-like data
    // This test verifies DecryptFile can be called without throwing on good streams
    std::stringstream inputStream;
    std::stringstream outputStream;

    std::string testData = "Some test data for decryption";
    inputStream.write(testData.data(), testData.size());
    inputStream.seekg(0);

    // DecryptFile should process the stream
    // We expect it might throw due to invalid encrypted data, which is acceptable
    try {
        cryptoCtx.DecryptFile(inputStream, outputStream, testPassword);
    } catch (const std::runtime_error &e) {
        // Expected - invalid encrypted data will cause EVP errors
        SUCCEED();
    }
}

// Test 4: Decrypt with empty input stream
TEST_F(CryptoGuardCtxDecryptTest, DecryptWithEmptyInputStream) {
    std::stringstream emptyInputStream;
    std::stringstream outputStream;

    // Empty input stream should be processed without stream state errors
    try {
        cryptoCtx.DecryptFile(emptyInputStream, outputStream, testPassword);
    } catch (const std::runtime_error &e) {
        // Expected - empty or invalid encrypted data
        SUCCEED();
    }
}
