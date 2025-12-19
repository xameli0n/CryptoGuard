#include "cmd_options.h"

#include <iostream>

namespace po = boost::program_options;

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help,h", "Show help message")("command,c", po::value<std::string>(),
                                                       "Command to execute: encrypt, decrypt or checksum")(
        "input,i", po::value<std::string>(),
        "Input file path")("output,o", po::value<std::string>(),
                           "Output file path")("password,p", po::value<std::string>(), "Password for encrypt/decrypt");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc_), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc_ << std::endl;
            return;
        }

        if (!vm.count("command")) {
            throw std::invalid_argument("Option --command is required");
        }

        const std::string cmd = vm["command"].as<std::string>();
        const auto it = commandMapping_.find(cmd);
        if (it == commandMapping_.end()) {
            throw std::invalid_argument("Unknown command: " + cmd);
        }

        command_ = it->second;

        if (vm.count("input")) {
            inputFile_ = vm["input"].as<std::string>();
        }

        if (vm.count("output")) {
            outputFile_ = vm["output"].as<std::string>();
        }

        if (vm.count("password")) {
            password_ = vm["password"].as<std::string>();
        }

        // Validate required parameters depending on command
        switch (command_) {
        case COMMAND_TYPE::ENCRYPT:
        case COMMAND_TYPE::DECRYPT:
            if (inputFile_.empty()) {
                throw std::invalid_argument("--input is required for encrypt/decrypt");
            }
            if (outputFile_.empty()) {
                throw std::invalid_argument("--output is required for encrypt/decrypt");
            }
            if (password_.empty()) {
                throw std::invalid_argument("--password is required for encrypt/decrypt");
            }
            break;

        case COMMAND_TYPE::CHECKSUM:
            if (inputFile_.empty()) {
                throw std::invalid_argument("--input is required for checksum");
            }
            break;
        }

    } catch (const std::exception &e) {
        std::cerr << "Error parsing options: " << e.what() << std::endl;
        throw;
    }
}

}  // namespace CryptoGuard
