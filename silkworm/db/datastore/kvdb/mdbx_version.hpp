// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <string_view>

namespace silkworm::datastore::kvdb {

/**
 * \brief Get libmdbx version for compatibility checks.
 * \return A string in git describe format.
 */
const char* libmdbx_version() noexcept;

//! Kind of match to perform between Erigon and Silkworm libmdbx versions
enum class MdbxVersionCheck : uint8_t {
    kNone,      /// no check at all
    kExact,     /// git-describe versions must match perfectly
    kSemantic,  /// compare semantic versions (<M1.m1.p1> == <M2.m2.p2>)
};

bool is_compatible_mdbx_version(std::string_view their_version, std::string_view our_version, MdbxVersionCheck check);

}  // namespace silkworm::datastore::kvdb
