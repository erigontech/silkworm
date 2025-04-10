// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "mdbx_version.hpp"

#include <string>
#include <vector>

#include <absl/strings/str_split.h>

#include <silkworm/infra/common/log.hpp>

#include "mdbx.hpp"

namespace silkworm::datastore::kvdb {

const char* libmdbx_version() noexcept {
    return ::mdbx::get_version().git.describe;
}

bool is_compatible_mdbx_version(std::string_view their_version, std::string_view our_version, MdbxVersionCheck check) {
    SILK_TRACE << "is_compatible_mdbx_version their_version: " << their_version << " our_version: " << our_version;
    bool compatible{false};
    switch (check) {
        case MdbxVersionCheck::kNone: {
            compatible = true;
        } break;
        case MdbxVersionCheck::kExact: {
            compatible = their_version == our_version;
        } break;
        case MdbxVersionCheck::kSemantic: {
            const std::vector<std::string> their_version_parts = absl::StrSplit(std::string(their_version), '.');
            const std::vector<std::string> our_version_parts = absl::StrSplit(std::string(our_version), '.');
            compatible = (their_version_parts.size() >= 3) &&
                         (our_version_parts.size() >= 3) &&
                         (their_version_parts[0] == our_version_parts[0]) &&
                         (their_version_parts[1] == our_version_parts[1]) &&
                         (their_version_parts[2] == our_version_parts[2]);
        }
    }
    return compatible;
}

}  // namespace silkworm::datastore::kvdb
