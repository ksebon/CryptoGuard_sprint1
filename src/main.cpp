#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>

namespace detail {

std::fstream OpenInputFile(const std::string &path) {
    std::fstream stream(path, std::ios::in | std::ios::binary);
    if (!stream.is_open()) {
        throw std::runtime_error{"Error open input file: " + path};
    }
    return stream;
}

std::fstream OpenOutputFile(const std::string &path) {
    std::fstream stream(path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!stream.is_open()) {
        throw std::runtime_error{"Error open output file: " + path};
    }
    return stream;
}

}  // namespace detail

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

        auto inStream = detail::OpenInputFile(options.GetInputFile());
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            auto outStream = detail::OpenOutputFile(options.GetOutputFile());
            cryptoCtx.EncryptFile(inStream, outStream, options.GetPassword());
            std::print("File encoded successfully\n");
            break;
        }

        case COMMAND_TYPE::DECRYPT: {
            auto outStream = detail::OpenOutputFile(options.GetOutputFile());
            cryptoCtx.DecryptFile(inStream, outStream, options.GetPassword());
            std::print("File decoded successfully\n");
            break;
        }

        case COMMAND_TYPE::CHECKSUM: {
            const std::string checksum = cryptoCtx.CalculateChecksum(inStream);
            std::print("Checksum: {}\n", checksum);
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