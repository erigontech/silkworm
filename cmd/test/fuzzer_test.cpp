// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <string>

#include <nlohmann/json.hpp>

#include <silkworm/rpc/test_util/api_test_database.hpp>

#include "address_sanitizer_fix.hpp"

using namespace silkworm::rpc::json_rpc;
using namespace silkworm::rpc::test_util;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    const auto request = std::string(reinterpret_cast<const char*>(Data), Size);
    if (!nlohmann::json::accept(request)) {
        return -1;
    }
    const auto request_json = nlohmann::json::parse(request);

    RpcApiE2ETest api_e2e_test;
    std::string reply;
    api_e2e_test.run<&RequestHandlerForTest::handle_request>(request, reply);

    if (!nlohmann::json::accept(reply)) {
        return -1;
    }
    const auto reply_json = nlohmann::json::parse(reply);

    return 0;
}
