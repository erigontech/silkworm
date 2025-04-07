// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "client_version.hpp"

#include <array>
#include <string>
#include <utility>

#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc {

//! Commit hash length is hard-coded at 4-bytes hex by spec
inline constexpr size_t kCommitSize = 4 * 2;

//! ClientVersionV1 as specified in https://github.com/ethereum/execution-apis/blob/main/src/engine/identification.md#clientversionv1
struct ClientVersionV1 {
    // NOLINTBEGIN(readability-identifier-naming)
    static constexpr std::string_view code{"SW"};        // never-changing value, hard-coded for efficiency
    static constexpr std::string_view name{"silkworm"};  // never-changing value, hard-coded for efficiency
    // NOLINTEND(readability-identifier-naming)

    std::string_view version;
    std::string_view commit;

    struct glaze {
        using T = ClientVersionV1;
        // NOLINTNEXTLINE(readability-identifier-naming)
        static constexpr auto value = glz::object(
            "code", &T::code,
            "name", &T::name,
            "version", &T::version,
            "commit", &T::commit);
    };
};

struct ClientVersionV1Reply {
    std::string_view jsonrpc = kJsonVersion;
    JsonRpcId id;
    std::array<ClientVersionV1, 1> result;  // array with just 1 element for any EL client (multiplexers may have many)

    struct glaze {
        using T = ClientVersionV1Reply;
        // NOLINTNEXTLINE(readability-identifier-naming)
        static constexpr auto value = glz::object(
            "jsonrpc", &T::jsonrpc,
            "id", &T::id,
            "result", &T::result);
    };
};

void make_glaze_json_content(const nlohmann::json& request_json, const ApplicationInfo& build_info, std::string& json_reply) {
    ClientVersionV1Reply reply{
        .id = make_jsonrpc_id(request_json),
        .result = {ClientVersionV1{
            .version = build_info.version,
            .commit = build_info.commit_hash.substr(0, kCommitSize),
        }},
    };

    glz::write_json(std::move(reply), json_reply);
}

}  // namespace silkworm::rpc
