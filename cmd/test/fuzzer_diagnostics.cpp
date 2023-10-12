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

#include <silkworm/silkrpc/test/api_test_database.hpp>

#include "address_sanitizer_fix.hpp"

void print_stack_trace() {
    void* trace[16];
    int trace_size = backtrace(trace, 16);
    char** messages = backtrace_symbols(trace, trace_size);
    [[maybe_unused]] auto _ = gsl::finally([&messages] { free(messages); });
    std::cout << "Stack Trace:" << std::endl;
    for (int i = 0; i < trace_size; i++) {
        std::cout << messages[i] << std::endl;

        // extract the address from the message
        char* address = strchr(messages[i], '[');
        if (address) {
            address++;
            char* end = strchr(address, ']');
            if (end) {
                *end = '\0';
                // use addr2line to get the file name and line number
                std::string command = "addr2line -e ./rpcdaemon_fuzz_debug " + std::string(address);
                auto command_result = system(command.c_str());
                if (command_result != 0) {
                    std::cout << "addr2line failed" << std::endl;
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
        ->description("Wrap JSON in '' to avoid shell escaping, e.g. '{\"jsonrpc\":\"2.0\",\"id\":1}'")
        ->default_val(R"({"jsonrpc":"2.0","id":1,"method":"debug_getRawBlock","params":["3"]})")
        ->required(false);

    app.add_option("-f", input_file, "Path to test file or directory")
        ->check(CLI::ExistingPath)
        ->required(false);

    CLI11_PARSE(app, argc, argv);

    if (input_str.empty() && input_file.empty()) {
        std::cerr << "Either input string or input file must be provided" << std::endl;
        return -1;
    }

    if (!input_file.empty()) {
        std::ifstream input_file_stream(input_file);
        input_str = std::string(std::istreambuf_iterator<char>(input_file_stream), std::istreambuf_iterator<char>());
    }

    if (!nlohmann::json::accept(input_str)) {
        std::cout << "Not valid json" << std::endl;
        return -1;
    }

    silkworm::rpc::http::Reply reply;

    try {
        auto context = silkworm::rpc::test::TestDatabaseContext();
        auto request_handler = new silkworm::rpc::test::RpcApiTestBase<silkworm::rpc::test::RequestHandler_ForTest>(context.db);
        auto request_json = nlohmann::json::parse(input_str);
        std::cout << "Request: " << request_json.dump(4) << std::endl;

        request_handler->run<&silkworm::rpc::test::RequestHandler_ForTest::handle_request>(input_str, reply);
    } catch (...) {
        std::exception_ptr eptr = std::current_exception();
        try {
            if (eptr) {
                std::rethrow_exception(eptr);
            }
        } catch (const std::exception& e) {
            std::cout << "Caught exception: " << e.what() << std::endl;
            print_stack_trace();
        }
    }

    std::cout << "Reply Status: " << static_cast<int>(reply.status) << std::endl;

    if (nlohmann::json::accept(reply.content)) {
        std::cout << "Reply Content: " << nlohmann::json::parse(reply.content).dump(4) << std::endl;
    } else {
        std::cout << "Reply Content: " << reply.content << std::endl;
    }

    return 0;
}
