#include "cmd_options.h"
#include <gtest/gtest.h>

namespace {

using CryptoGuard::ProgramOptions;
using CommandType = ProgramOptions::COMMAND_TYPE;

class ArgBuilder {
public:
    explicit ArgBuilder(std::initializer_list<std::string> args) {
        storage_.reserve(args.size());
        argv_.reserve(args.size());
        for (const auto &arg : args) {
            storage_.push_back(arg);
            argv_.push_back(storage_.back().data());
        }
    }

    int argc() const { return static_cast<int>(argv_.size()); }

    char **argv() { return argv_.data(); }

private:
    std::vector<std::string> storage_;
    std::vector<char *> argv_;
};

}  // namespace

// успешные команды
TEST(ProgramOptions, EncryptOption) {
    ArgBuilder args{"CryptoGuard", "--command", "encrypt",    "--input", "in.txt",
                    "--output",    "out.enc",   "--password", "secret"};
    ProgramOptions options;

    ASSERT_NO_THROW(options.Parse(args.argc(), args.argv()));
    EXPECT_EQ(options.GetCommand(), CommandType::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "in.txt");
    EXPECT_EQ(options.GetOutputFile(), "out.enc");
    EXPECT_EQ(options.GetPassword(), "secret");
}

TEST(ProgramOptions, DecryptOption) {
    ArgBuilder args{"CryptoGuard", "--command", "decrypt",    "--input", "out.enc",
                    "--output",    "in.txt",    "--password", "secret"};
    ProgramOptions options;

    ASSERT_NO_THROW(options.Parse(args.argc(), args.argv()));
    EXPECT_EQ(options.GetCommand(), CommandType::DECRYPT);
    EXPECT_EQ(options.GetInputFile(), "out.enc");
    EXPECT_EQ(options.GetOutputFile(), "in.txt");
    EXPECT_EQ(options.GetPassword(), "secret");
}

TEST(ProgramOptions, ChecksumOption) {
    ArgBuilder args{"CryptoGuard", "--command", "checksum", "--input", "file.bin"};
    ProgramOptions options;

    ASSERT_NO_THROW(options.Parse(args.argc(), args.argv()));
    EXPECT_EQ(options.GetCommand(), CommandType::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "file.bin");
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

// ошибочные команды
TEST(ProgramOptions, NotCommandThrows) {
    ArgBuilder args{"CryptoGuard", "--input", "in.txt"};
    ProgramOptions options;

    EXPECT_THROW(options.Parse(args.argc(), args.argv()), boost::program_options::required_option);
}

TEST(ProgramOptions, UnknownCommandThrows) {
    ArgBuilder args{"CryptoGuard", "--command", "compress", "--input", "in.txt"};
    ProgramOptions options;

    EXPECT_THROW(options.Parse(args.argc(), args.argv()), std::invalid_argument);
}

TEST(ProgramOptions, NotPasswordForDecrypt) {
    ArgBuilder args{"CryptoGuard", "--command", "decrypt", "--input", "in.txt", "--output", "out.txt"};
    ProgramOptions options;

    EXPECT_THROW(options.Parse(args.argc(), args.argv()), std::invalid_argument);
}