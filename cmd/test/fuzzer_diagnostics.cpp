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

void printStackTrace() {
    void* trace[16];
    int trace_size = backtrace(trace, 16);
    char** messages = backtrace_symbols(trace, trace_size);
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
    free(messages);
}

int main(int argc, char* argv[]) {
    const auto DEFAULT_REQUEST = R"({"jsonrpc":"2.0","id":1,"method":"eth_getTransactionByHash","params":["0x54b25c11650dca0253ef7b91b5415680eea8dac54b029863e12db48908ad386c"]})";

    CLI::App app{"Debugs or rerun a single fuzzer test"};

    std::string input_str;
    std::string input_file;

    app.add_option("input", input_str, "Input string")
        ->default_val(DEFAULT_REQUEST)
        ->description("Wrap JSON in '' to avoid shell escaping, e.g. '{\"jsonrpc\":\"2.0\",\"id\":1}'")
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
        std::cout << "Not valid jsona" << std::endl;
        return -1;
    }

    silkworm::rpc::http::Reply reply;

    try {
        static auto db = silkworm::rpc::test::InitializeTestBase();
        static auto request_handler = new silkworm::rpc::test::RpcApiTestBase<silkworm::rpc::test::RequestHandler_ForTest>(db);

        auto request_json = nlohmann::json::parse(input_str);
        std::cout << "Request: " << request_json.dump(4) << std::endl;

        request_handler->run<&silkworm::rpc::test::RequestHandler_ForTest::handle_request>(input_str, reply);

        auto db_path = db.get_path();
        db.close();
        std::filesystem::remove_all(db_path);
    } catch (...) {
        std::exception_ptr eptr = std::current_exception();
        try {
            if (eptr) {
                std::rethrow_exception(eptr);
            }
        } catch (const std::exception& e) {
            std::cout << "Caught exception: " << e.what() << std::endl;
            printStackTrace();
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
