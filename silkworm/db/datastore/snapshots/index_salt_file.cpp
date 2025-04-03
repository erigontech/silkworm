// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "index_salt_file.hpp"

#include <fstream>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/endian.hpp>

namespace silkworm::snapshots {

using namespace std;

uint32_t IndexSaltFile::load() const {
    Bytes data(sizeof(uint32_t), 0);
    ifstream file{path_, std::ios::binary};
    file.exceptions(ios::failbit | ios::badbit);
    file.read(byte_ptr_cast(data.data()), static_cast<streamsize>(data.size()));
    return endian::load_big_u32(data.data());
}

void IndexSaltFile::save(uint32_t value) const {
    Bytes data(sizeof(uint32_t), 0);
    endian::store_big_u32(data.data(), value);
    ofstream file{path_, std::ios::binary | std::ios::trunc};
    file.exceptions(ios::failbit | ios::badbit);
    file.write(byte_ptr_cast(data.data()), static_cast<streamsize>(data.size()));
}

}  // namespace silkworm::snapshots
