#include "../include/cmd_options.h"
#include <boost/program_options/value_semantic.hpp>
#include <iostream>

namespace po = boost::program_options;

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {

    desc_.add_options()("help", "Show help message")("command", po::value<std::string>()->required(),
                                                     "Command to execute (encrypt, decrypt, checksum)")(
        "input", po::value<std::string>()->default_value(""),
        "Path to input file")("output", po::value<std::string>()->default_value(""), "Path to output file")(
        "password", po::value<std::string>()->default_value(""), "Password for encryption/decryption");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::ValidateOptions() const {
    if (inputFile_.empty()) {
        throw std::invalid_argument("Input file is empty");
    }

    if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
        if (outputFile_.empty()) {
            throw std::invalid_argument("Output file is empty");
        }
        if (password_.empty()) {
            throw std::invalid_argument("Password is empty");
        }
    }
}

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);

    if (vm.count("help")) {
        std::cout << desc_ << "\n";
        std::exit(0);
    }

    po::notify(vm);

    // маппинг строковых команд на enum COMMAND_TYPE
    const auto &command = vm["command"].as<std::string>();
    auto it = commandMapping_.find(command);
    if (it == commandMapping_.end()) {
        throw std::invalid_argument("Unknown command: " + command);
    }
    command_ = it->second;

    inputFile_ = vm["input"].as<std::string>();
    outputFile_ = vm["output"].as<std::string>();
    password_ = vm["password"].as<std::string>();

    ValidateOptions();
}

}  // namespace CryptoGuard
