/*
   Copyright 2022 The Silkworm Authors

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

#pragma once

#include <stdexcept>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

namespace silkworm::etl {

//! \brief Converts a system error code into its message
//! \remarks Removes the deprecation strerror
std::string errno2str(int err_code);

class etl_error : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

// Head of each data chunk on file
union head_t {
    uint32_t lengths[2];
    uint8_t bytes[8];
};

// A data chunk on file or buffer
struct Entry {
    Entry() = default;
    Entry(const Entry&) = default;
    Entry(Entry&&) = default;
    Entry(const Bytes& k, const Bytes& v) : key(k), value(v) {}
    Entry(Bytes&& k, Bytes&& v) : key(std::move(k)), value(std::move(v)) {}
    Entry& operator=(const Entry&) = default;
    Entry& operator=(Entry&&) = default;
    // remove all the above constructors switching to clang version >= 16

    Bytes key;
    Bytes value;
    [[nodiscard]] size_t size() const noexcept { return key.size() + value.size(); }
};

bool operator<(const Entry& a, const Entry& b);

}  // namespace silkworm::etl
