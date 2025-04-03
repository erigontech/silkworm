// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <stdexcept>

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::datastore::etl {

class EtlError : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

// Head of each data chunk on file
union EntryHeader {
    uint32_t lengths[2];
    uint8_t bytes[8];
};

// A data chunk on file or buffer
struct Entry {
    Entry() = default;
    Entry(const Entry&) = default;
    Entry(Entry&&) = default;
    Entry(Bytes k, Bytes v) : key(std::move(k)), value(std::move(v)) {}
    Entry& operator=(const Entry&) = default;
    Entry& operator=(Entry&&) = default;
    // remove all the above constructors switching to clang version >= 16

    Bytes key;
    Bytes value;

    size_t size() const noexcept { return key.size() + value.size(); }
};

inline bool operator<(const Entry& a, const Entry& b) {
    auto diff{a.key.compare(b.key)};
    if (diff == 0) {
        return a.value < b.value;
    }
    return diff < 0;
}

}  // namespace silkworm::datastore::etl
