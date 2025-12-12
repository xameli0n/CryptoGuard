#include "cmd_options.h"
#include <gtest/gtest.h>

using namespace CryptoGuard;

static std::vector<char *> BuildArgv(const std::vector<std::string> &args) {
    std::vector<char *> argv;
    argv.reserve(args.size());
    for (const auto &s : args) {
        argv.push_back(const_cast<char *>(s.c_str()));
    }
    return argv;
}

TEST(ProgramOptions, HelpDoesNotThrow) {
    ProgramOptions opts;
    auto argv = BuildArgv({"prog", "--help"});
    EXPECT_NO_THROW(opts.Parse(static_cast<int>(argv.size()), argv.data()));
}

TEST(ProgramOptions, MissingCommandThrows) {
    ProgramOptions opts;
    auto argv = BuildArgv({"prog", "-i", "input.txt"});
    EXPECT_THROW(opts.Parse(static_cast<int>(argv.size()), argv.data()), std::exception);
}

TEST(ProgramOptions, InvalidCommandThrows) {
    ProgramOptions opts;
    auto argv = BuildArgv({"prog", "--command", "badcmd", "-i", "input.txt"});
    EXPECT_THROW(opts.Parse(static_cast<int>(argv.size()), argv.data()), std::exception);
}

TEST(ProgramOptions, EncryptParsesAllOptions) {
    ProgramOptions opts;
    auto argv = BuildArgv({"prog", "--command", "encrypt", "-i", "in.txt", "-o", "out.txt", "-p", "pass"});
    EXPECT_NO_THROW(opts.Parse(static_cast<int>(argv.size()), argv.data()));
    EXPECT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(opts.GetInputFile(), "in.txt");
    EXPECT_EQ(opts.GetOutputFile(), "out.txt");
    EXPECT_EQ(opts.GetPassword(), "pass");
}

TEST(ProgramOptions, DecryptMissingPasswordThrows) {
    ProgramOptions opts;
    auto argv = BuildArgv({"prog", "--command", "decrypt", "-i", "in.txt", "-o", "out.txt"});
    EXPECT_THROW(opts.Parse(static_cast<int>(argv.size()), argv.data()), std::exception);
}

TEST(ProgramOptions, ChecksumParsesInputOnly) {
    ProgramOptions opts;
    auto argv = BuildArgv({"prog", "--command", "checksum", "-i", "in.txt"});
    EXPECT_NO_THROW(opts.Parse(static_cast<int>(argv.size()), argv.data()));
    EXPECT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(opts.GetInputFile(), "in.txt");
}
