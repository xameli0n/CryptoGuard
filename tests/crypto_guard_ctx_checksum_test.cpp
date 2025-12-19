#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>

using namespace CryptoGuard;

class CryptoGuardCtxChecksumTest : public ::testing::Test {
protected:
    CryptoGuardCtx cryptoCtx;
};

// Test 1: Calculate checksum of simple text
TEST_F(CryptoGuardCtxChecksumTest, CalculateChecksumSimpleText) {
    std::stringstream inputStream;
    const std::string testData = "Hello, World!";

    inputStream.write(testData.data(), testData.size());
    inputStream.seekg(0);

    std::string checksum;
    EXPECT_NO_THROW(checksum = cryptoCtx.CalculateChecksum(inputStream));

    // Verify checksum is not empty
    EXPECT_FALSE(checksum.empty());

    // Verify checksum is hexadecimal string (64 characters for SHA-256)
    EXPECT_EQ(checksum.length(), 64);

    // Verify all characters are hexadecimal
    for (char c : checksum) {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }

    // Known SHA-256 hash for "Hello, World!"
    // echo -n "Hello, World!" | sha256sum
    const std::string expectedHash = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f";
    EXPECT_EQ(checksum, expectedHash);
}

// Test 2: Calculate checksum of empty input
TEST_F(CryptoGuardCtxChecksumTest, CalculateChecksumEmptyInput) {
    std::stringstream emptyStream;

    std::string checksum;
    EXPECT_NO_THROW(checksum = cryptoCtx.CalculateChecksum(emptyStream));

    // Verify checksum is not empty (SHA-256 of empty string is valid)
    EXPECT_FALSE(checksum.empty());
    EXPECT_EQ(checksum.length(), 64);

    // Known SHA-256 hash for empty string
    // echo -n "" | sha256sum
    const std::string expectedHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    EXPECT_EQ(checksum, expectedHash);
}

// Test 3: Calculate checksum with bad input stream throws
TEST_F(CryptoGuardCtxChecksumTest, CalculateChecksumWithBadStreamThrows) {
    std::stringstream badStream;

    // Set stream to bad state
    badStream.setstate(std::ios::badbit);

    EXPECT_THROW(cryptoCtx.CalculateChecksum(badStream), std::runtime_error);
}

// Test 4: Calculate checksum of larger data
TEST_F(CryptoGuardCtxChecksumTest, CalculateChecksumLargeData) {
    std::stringstream inputStream;

    // Create data larger than buffer size (1024 bytes)
    std::string largeData(2048, 'X');
    inputStream.write(largeData.data(), largeData.size());
    inputStream.seekg(0);

    std::string checksum;
    EXPECT_NO_THROW(checksum = cryptoCtx.CalculateChecksum(inputStream));

    // Verify checksum format
    EXPECT_EQ(checksum.length(), 64);

    // Verify checksum is consistent (calculate again)
    inputStream.clear();
    inputStream.seekg(0);
    std::string checksum2 = cryptoCtx.CalculateChecksum(inputStream);
    EXPECT_EQ(checksum, checksum2);
}
