#include "crypto_guard_ctx.h"

#include <array>
#include <iomanip>
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace CryptoGuard {

// ============================================================================
// Helper function for OpenSSL error handling
// ============================================================================

/**
 * @brief Get detailed OpenSSL error message
 * @param context Context description for the error
 * @return Formatted error message with OpenSSL error details
 */
static std::string GetOpenSSLError(const std::string &context) {
    unsigned long errCode = ERR_get_error();
    if (errCode == 0) {
        return context;
    }

    char errBuf[256];
    ERR_error_string_n(errCode, errBuf, sizeof(errBuf));

    std::stringstream ss;
    ss << context << ": " << errBuf << " (error code: 0x" << std::hex << errCode << ")";
    return ss.str();
}

// ============================================================================
// AesCipherParams - AES cipher configuration structure
// ============================================================================

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

// ============================================================================
// Helper function to create cipher params from password
// ============================================================================

AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error(GetOpenSSLError("Failed to create a key from password"));
    }

    return params;
}

// ============================================================================
// CryptoGuardCtx::Impl - Private implementation
// ============================================================================

class CryptoGuardCtx::Impl {
public:
    Impl();
    ~Impl();

    // API - corresponding to CryptoGuardCtx public interface
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream);
};

// ============================================================================
// CryptoGuardCtx::Impl constructor and destructor with EVP initialization
// ============================================================================

CryptoGuardCtx::Impl::Impl() {
    // Initialize OpenSSL algorithms
    OpenSSL_add_all_algorithms();

    // Load error strings for better error reporting
    ERR_load_crypto_strings();
}

CryptoGuardCtx::Impl::~Impl() {
    // Clean up OpenSSL resources in reverse order of initialization
    EVP_cleanup();
    ERR_free_strings();
}

// ============================================================================
// CryptoGuardCtx::Impl API implementation (declarations only for now)
// ============================================================================

void CryptoGuardCtx::Impl::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    // Check input and output stream states
    if (!inStream.good()) {
        throw std::runtime_error("EncryptFile: Input stream is not in a good state");
    }
    if (!outStream.good()) {
        throw std::runtime_error("EncryptFile: Output stream is not in a good state");
    }

    // Create cipher parameters from password
    AesCipherParams params = CreateChiperParamsFromPassword(password);
    params.encrypt = 1;  // 1 for encryption

    // Create EVP context with custom deleter using std::unique_ptr
    // The deleter ensures proper cleanup even if exceptions are thrown
    auto ctx_deleter = [](EVP_CIPHER_CTX *ctx) {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    };
    std::unique_ptr<EVP_CIPHER_CTX, decltype(ctx_deleter)> ctx(EVP_CIPHER_CTX_new(), ctx_deleter);

    if (!ctx) {
        throw std::runtime_error(GetOpenSSLError("Failed to create EVP cipher context for encryption"));
    }

    // Initialize cipher context
    if (EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt) !=
        1) {
        throw std::runtime_error(GetOpenSSLError("Failed to initialize EVP cipher context for encryption"));
    }

    // Buffers for input/output data
    constexpr size_t BUFFER_SIZE = 1024;
    std::vector<unsigned char> inBuf(BUFFER_SIZE);
    std::vector<unsigned char> outBuf(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    int outLen;

    // Process input stream in chunks
    while (inStream.read(reinterpret_cast<char *>(inBuf.data()), BUFFER_SIZE) || inStream.gcount() > 0) {
        int inLen = inStream.gcount();

        if (inLen > 0) {
            if (EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inLen) != 1) {
                throw std::runtime_error(GetOpenSSLError("EVP_CipherUpdate failed during encryption"));
            }

            // Check output stream state before writing
            if (!outStream.good()) {
                throw std::runtime_error("EncryptFile: Output stream is not in a good state after cipher update");
            }

            // Write encrypted data to output stream
            outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);

            if (!outStream.good()) {
                throw std::runtime_error("EncryptFile: Failed to write encrypted data to output stream");
            }
        }

        // Break if we've reached EOF
        if (inStream.eof()) {
            break;
        }
    }

    // Handle final block with padding
    if (EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen) != 1) {
        throw std::runtime_error(GetOpenSSLError("EVP_CipherFinal_ex failed during encryption"));
    }

    // Write final block if needed
    if (outLen > 0) {
        if (!outStream.good()) {
            throw std::runtime_error("EncryptFile: Output stream is not in a good state before final write");
        }

        outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);

        if (!outStream.good()) {
            throw std::runtime_error("EncryptFile: Failed to write final encrypted block to output stream");
        }
    }
}

void CryptoGuardCtx::Impl::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    // Check input and output stream states
    if (!inStream.good()) {
        throw std::runtime_error("DecryptFile: Input stream is not in a good state");
    }
    if (!outStream.good()) {
        throw std::runtime_error("DecryptFile: Output stream is not in a good state");
    }

    // Create cipher parameters from password
    AesCipherParams params = CreateChiperParamsFromPassword(password);
    params.encrypt = 0;  // 0 for decryption

    // Create EVP context with custom deleter
    auto ctx_deleter = [](EVP_CIPHER_CTX *ctx) {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    };
    std::unique_ptr<EVP_CIPHER_CTX, decltype(ctx_deleter)> ctx(EVP_CIPHER_CTX_new(), ctx_deleter);

    if (!ctx) {
        throw std::runtime_error(GetOpenSSLError("Failed to create EVP cipher context for decryption"));
    }

    // Initialize cipher context
    if (EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt) !=
        1) {
        throw std::runtime_error(GetOpenSSLError("Failed to initialize EVP cipher context for decryption"));
    }

    // Buffers for input/output data
    constexpr size_t BUFFER_SIZE = 1024;
    std::vector<unsigned char> inBuf(BUFFER_SIZE);
    std::vector<unsigned char> outBuf(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    int outLen;

    // Process input stream in chunks
    while (inStream.read(reinterpret_cast<char *>(inBuf.data()), BUFFER_SIZE) || inStream.gcount() > 0) {
        int inLen = inStream.gcount();

        if (inLen > 0) {
            if (EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inLen) != 1) {
                throw std::runtime_error(GetOpenSSLError("EVP_CipherUpdate failed during decryption"));
            }

            // Check output stream state before writing
            if (!outStream.good()) {
                throw std::runtime_error("DecryptFile: Output stream is not in a good state after cipher update");
            }

            // Write decrypted data to output stream
            outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);

            if (!outStream.good()) {
                throw std::runtime_error("DecryptFile: Failed to write decrypted data to output stream");
            }
        }

        // Break if we've reached EOF
        if (inStream.eof()) {
            break;
        }
    }

    // Handle final block and verify padding
    if (EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen) != 1) {
        throw std::runtime_error(
            GetOpenSSLError("EVP_CipherFinal_ex failed during decryption (possibly wrong password or corrupted data)"));
    }

    // Write final block if needed
    if (outLen > 0) {
        if (!outStream.good()) {
            throw std::runtime_error("DecryptFile: Output stream is not in a good state before final write");
        }

        outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);

        if (!outStream.good()) {
            throw std::runtime_error("DecryptFile: Failed to write final decrypted block to output stream");
        }
    }
}

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::iostream &inStream) {
    // Check input stream state
    if (!inStream.good()) {
        throw std::runtime_error("CalculateChecksum: Input stream is not in a good state");
    }

    // Create EVP message digest context with custom deleter
    auto md_ctx_deleter = [](EVP_MD_CTX *ctx) {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    };
    std::unique_ptr<EVP_MD_CTX, decltype(md_ctx_deleter)> mdCtx(EVP_MD_CTX_new(), md_ctx_deleter);

    if (!mdCtx) {
        throw std::runtime_error(GetOpenSSLError("Failed to create EVP message digest context"));
    }

    // Initialize SHA-256 hash context
    if (EVP_DigestInit_ex(mdCtx.get(), EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error(GetOpenSSLError("Failed to initialize SHA-256 digest"));
    }

    // Buffer for reading input data
    constexpr size_t BUFFER_SIZE = 1024;
    std::vector<unsigned char> buffer(BUFFER_SIZE);

    // Process input stream in chunks
    while (inStream.read(reinterpret_cast<char *>(buffer.data()), BUFFER_SIZE)) {
        int bytesRead = inStream.gcount();

        // Check input stream state before updating hash
        if (!inStream.good() && !inStream.eof()) {
            throw std::runtime_error("CalculateChecksum: Input stream error during reading");
        }

        if (bytesRead > 0) {
            if (EVP_DigestUpdate(mdCtx.get(), buffer.data(), bytesRead) != 1) {
                throw std::runtime_error(GetOpenSSLError("Failed to update SHA-256 digest"));
            }
        }
    }

    // Handle last chunk (when read() fails due to EOF)
    int lastBytes = inStream.gcount();
    if (lastBytes > 0) {
        if (EVP_DigestUpdate(mdCtx.get(), buffer.data(), lastBytes) != 1) {
            throw std::runtime_error(GetOpenSSLError("Failed to update SHA-256 digest with final chunk"));
        }
    }

    // Finalize hash and get result
    std::array<unsigned char, EVP_MAX_MD_SIZE> hash;
    unsigned int hashLen = 0;

    if (EVP_DigestFinal_ex(mdCtx.get(), hash.data(), &hashLen) != 1) {
        throw std::runtime_error(GetOpenSSLError("Failed to finalize SHA-256 digest"));
    }

    // Convert hash to hexadecimal string
    std::stringstream hexStream;
    hexStream << std::hex << std::setfill('0');

    for (unsigned int i = 0; i < hashLen; ++i) {
        hexStream << std::setw(2) << static_cast<int>(hash[i]);
    }

    return hexStream.str();
}

// ============================================================================
// CryptoGuardCtx - Public interface
// ============================================================================

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
