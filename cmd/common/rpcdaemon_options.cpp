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

#include "rpcdaemon_options.hpp"

#include <algorithm>
#include <regex>

#include <silkworm/silkrpc/common/constants.hpp>

#include "ip_endpoint_option.hpp"

namespace silkworm::cmd::common {

//! CLI11 validator for ETH1 JSON API namespace specification
struct ApiSpecValidator : public CLI::Validator {
    explicit ApiSpecValidator(bool allow_empty = false) {
        func_ = [&allow_empty](const std::string& value) -> std::string {
            if (value.empty() && allow_empty) {
                return {};
            }

            // Parse the entire API namespace specification, i.e. comma-separated list of API namespaces
            const std::regex pattern(R"([,]+)");
            std::smatch matches;
            if (!std::regex_match(value, matches, pattern)) {
                return "Value " + value + " is not a valid API namespace specification";
            }

            // Validate each specified API namespace
            for (const auto& sub_match : matches) {
                const auto ns = sub_match.str();
                const auto it = std::find(kAllEth1Namespaces.cbegin(), kAllEth1Namespaces.cend(), ns.c_str());
                if (it == kAllEth1Namespaces.cend()) {
                    return "Value " + ns + " is not a valid API namespace";
                }
            }

            return {};
        };
    }
};

void add_rpcdaemon_options(CLI::App& cli, silkworm::rpc::DaemonSettings& settings) {
    add_option_ip_endpoint(cli, "--eth.addr", settings.eth_end_point,
                           "Execution Layer JSON RPC API local end-point as <address>:<port>");
    add_option_ip_endpoint(cli, "--engine.addr", settings.engine_end_point,
                           "Engine JSON RPC API local end-point as <address>:<port>");

    cli.add_option("--private.addr", settings.private_api_addr)
        ->description("Silkworm gRPC service remote end-point as <address>:<port>")
        ->capture_default_str();

    cli.add_option("--workers", settings.num_workers)
        ->description("Number of worker threads dedicated to long-running tasks")
        ->check(CLI::Range(1, 1024))
        ->capture_default_str();

    cli.add_option("--api", settings.eth_api_spec)
        ->description("Execution Layer JSON RPC API namespaces as comma-separated list of strings")
        ->check(ApiSpecValidator())
        ->capture_default_str();

    cli.add_option("--jwt", settings.jwt_secret_file)
        ->description("JWT secret file to ensure safe connection between CL and EL as file path")
        ->capture_default_str();

    cli.add_flag("--skip_protocol_check", settings.skip_protocol_check)
        ->description("Flag indicating if gRPC protocol version check should be skipped")
        ->capture_default_str();
}

}  // namespace silkworm::cmd::common
