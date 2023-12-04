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
#include <array>

#include <absl/strings/str_split.h>

#include <silkworm/rpc/common/constants.hpp>

#include "ip_endpoint_option.hpp"

namespace silkworm::cmd::common {

//! All Ethereum EL JSON RPC API namespaces (standard + custom)
constexpr std::array kAllEth1Namespaces{
    kAdminApiNamespace,
    kDebugApiNamespace,
    kEthApiNamespace,
    kNetApiNamespace,
    kParityApiNamespace,
    kTraceApiNamespace,
    kTxPoolApiNamespace,
    kWeb3ApiNamespace,
    kErigonApiNamespace,
    kOtterscanApiNamespace};

//! Compute the maximum number of chars in comma-separated list of all API namespaces
static const auto kApiNamespaceListMaxChars{
    std::accumulate(kAllEth1Namespaces.cbegin(), kAllEth1Namespaces.cend(), 0, [](size_t sum, auto s) {
        return sum + std::strlen(s);
    }) +
    kAllEth1Namespaces.size() - 1};

//! CLI11 validator for ETH1 JSON API namespace specification
struct ApiSpecValidator : public CLI::Validator {
    explicit ApiSpecValidator(bool allow_empty = false) {
        func_ = [&allow_empty](const std::string& value) -> std::string {
            if (value.empty() && allow_empty) {
                return {};
            }
            if (value.size() > kApiNamespaceListMaxChars) {
                return "Value " + value + " is too long for valid API namespace specification";
            }

            // Parse the entire API namespace specification, i.e. comma-separated list of API namespaces
            for (const auto ns : absl::StrSplit(value, ",")) {
                const auto it = std::find(kAllEth1Namespaces.cbegin(), kAllEth1Namespaces.cend(), ns);
                if (it == kAllEth1Namespaces.cend()) {
                    return "Value " + std::string{ns} + " is not a valid API namespace";
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

    cli.add_option("--http.cors.domain", settings.cors_domain)
        ->description("Comma separated list of domains from which to accept cross origin requests (browser enforced)")
        ->delimiter(',')
        ->required(false);

    cli.add_flag("--skip_protocol_check", settings.skip_protocol_check)
        ->description("Flag indicating if gRPC protocol version check should be skipped")
        ->capture_default_str();

    cli.add_flag("--erigon_compatibility", settings.erigon_json_rpc_compatibility)
        ->description("Flag indicating if strict compatibility with Erigon RpcDaemon is enabled")
        ->capture_default_str();
}

}  // namespace silkworm::cmd::common
