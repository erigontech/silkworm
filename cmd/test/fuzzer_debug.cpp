#include <execinfo.h>

#include <cstdlib>
#include <exception>
#include <iostream>

#include <CLI/CLI.hpp>

#include "fuzzer.cpp"

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
                system(command.c_str());
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

    silkworm::rpc::http::Reply reply;

    try {
        static auto db = InitializeTestBase();
        static auto request_handler = new RpcApiTestBase<RequestHandler_ForTest>(db);

        auto request_json = nlohmann::json::parse(input_str);
        std::cout << "Request: " << request_json.dump(4) << std::endl;

        request_handler->run<&RequestHandler_ForTest::request_and_create_reply>(request_json, reply);
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

    auto reply_json = nlohmann::json::parse(reply.content);
    if (reply_json.is_structured()) {
        std::cout << "Reply Content: " << reply_json.dump(4) << std::endl;
    } else {
        std::cout << "Reply Content: " << reply.content << std::endl;
    }
}
