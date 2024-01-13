/*
   Copyright 2023 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <execinfo.h>

#include <cstdlib>
#include <exception>
#include <iostream>

#include <CLI/CLI.hpp>
#include <gsl/util>

#include <silkworm/rpc/http/channel.hpp>
#include <silkworm/rpc/test/api_test_database.hpp>

#include "address_sanitizer_fix.hpp"

void print_stack_trace() {
    void* trace[16];
    int trace_size = backtrace(trace, 16);
    char** messages = backtrace_symbols(trace, trace_size);
    [[maybe_unused]] auto _ = gsl::finally([&messages] { free(messages); });
    std::cout << "Stack Trace:\n";
    for (int i = 0; i < trace_size; i++) {
        std::cout << messages[i] << "\n";

        // extract the address from the message
        char* address = strchr(messages[i], '[');
        if (address) {
            address++;
            char* end = strchr(address, ']');
            if (end) {
                *end = '\0';
                // use addr2line to get the file name and line number
                std::string command = "addr2line -e ./rpcdaemon_fuzzer_diagnostics " + std::string(address);
                auto command_result = system(command.c_str());  // NOLINT(cert-*)
                if (command_result != 0) {
                    std::cout << "addr2line failed\n";
                }
            }
        }
    }
}

int main(int argc, char* argv[]) {
    CLI::App app{"Debugs or rerun a single fuzzer test"};

    std::string input_str;
    std::string input_file;

    app.add_option("input", input_str, "Input string")
        ->description(R"(Wrap JSON in '' to avoid shell escaping, e.g. '{"jsonrpc":"2.0","id":1}')")
        ->required(false);

    app.add_option("-f", input_file, "Path to the JSON request file")
        ->check(CLI::ExistingFile)
        ->required(false);

    CLI11_PARSE(app, argc, argv)

    if (input_str.empty() && input_file.empty()) {
        std::cerr << "Either input string or input file must be provided" << "\n";
        return -1;
    }

    if (!input_file.empty()) {
        std::ifstream input_file_stream(input_file);
        input_str = std::string(std::istreambuf_iterator<char>(input_file_stream), std::istreambuf_iterator<char>());
    }

    if (!nlohmann::json::accept(input_str)) {
        std::cout << "Not valid json: " << input_str << "\n";
    } else {
        auto request_json = nlohmann::json::parse(input_str);
        std::cout << "Request: " << request_json.dump(4) << "\n";
    }

    silkworm::rpc::Channel::Response reply;

    try {
        auto context = silkworm::rpc::test::TestDatabaseContext();
        auto request_handler = new silkworm::rpc::test::RpcApiTestBase<silkworm::rpc::test::RequestHandler_ForTest>(context.db);

        request_handler->run<&silkworm::rpc::test::RequestHandler_ForTest::handle_request>(input_str, reply);
    } catch (...) {
        std::exception_ptr eptr = std::current_exception();
        try {
            if (eptr) {
                std::rethrow_exception(eptr);
            }
        } catch (const std::exception& e) {
            std::cout << "Caught exception: " << e.what() << "\n";
            print_stack_trace();
        }
    }

    std::cout << "Reply Status: " << static_cast<int>(reply.status) << "\n";

    if (nlohmann::json::accept(reply.content)) {
        std::cout << "Reply Content: " << nlohmann::json::parse(reply.content).dump(4) << "\n";
    } else {
        std::cout << "Reply Content: " << reply.content << "\n";
    }

    return 0;
}
