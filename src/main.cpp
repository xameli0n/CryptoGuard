#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <iostream>
#include <print>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            // Open input and output files
            std::fstream inputFile(options.GetInputFile(), std::ios::in | std::ios::binary);
            if (!inputFile.good()) {
                throw std::runtime_error("Failed to open input file: " + options.GetInputFile());
            }

            std::fstream outputFile(options.GetOutputFile(), std::ios::out | std::ios::binary);
            if (!outputFile.good()) {
                throw std::runtime_error("Failed to create output file: " + options.GetOutputFile());
            }

            // Encrypt the file
            cryptoCtx.EncryptFile(inputFile, outputFile, options.GetPassword());

            inputFile.close();
            outputFile.close();

            std::print("File encrypted successfully: {} -> {}\n", options.GetInputFile(), options.GetOutputFile());
            break;
        }

        case COMMAND_TYPE::DECRYPT: {
            // Open input and output files
            std::fstream inputFile(options.GetInputFile(), std::ios::in | std::ios::binary);
            if (!inputFile.good()) {
                throw std::runtime_error("Failed to open input file: " + options.GetInputFile());
            }

            std::fstream outputFile(options.GetOutputFile(), std::ios::out | std::ios::binary);
            if (!outputFile.good()) {
                throw std::runtime_error("Failed to create output file: " + options.GetOutputFile());
            }

            // Decrypt the file
            cryptoCtx.DecryptFile(inputFile, outputFile, options.GetPassword());

            inputFile.close();
            outputFile.close();

            std::print("File decrypted successfully: {} -> {}\n", options.GetInputFile(), options.GetOutputFile());
            break;
        }

        case COMMAND_TYPE::CHECKSUM: {
            // Open input file
            std::fstream inputFile(options.GetInputFile(), std::ios::in | std::ios::binary);
            if (!inputFile.good()) {
                throw std::runtime_error("Failed to open input file: " + options.GetInputFile());
            }

            // Calculate checksum
            std::string checksum = cryptoCtx.CalculateChecksum(inputFile);
            inputFile.close();

            std::print("SHA-256 checksum of {}: {}\n", options.GetInputFile(), checksum);
            break;
        }

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}