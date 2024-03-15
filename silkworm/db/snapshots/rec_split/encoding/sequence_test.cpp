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

#include "sequence.hpp"

#include <sstream>
#include <stdexcept>

#include <catch2/catch.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::snapshots::rec_split::encoding {

TEST_CASE("Uint64Sequence", "[silkworm][snapshots][recsplit][sequence]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    Uint64Sequence output_sequence{0, 11, 21, 31, 41, 51, 61};

    std::stringstream ss;
    ss << output_sequence;

    Uint64Sequence input_sequence;
    ss >> input_sequence;

    CHECK(input_sequence == output_sequence);
}

TEST_CASE("Uint64Sequence: size too big", "[silkworm][snapshots][recsplit][sequence]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};

    std::stringstream ss;
    Bytes invalid_size_buffer(sizeof(uint64_t), '\0');
    endian::store_big_u64(invalid_size_buffer.data(), 49287623586282974);
    ss.write(byte_ptr_cast(invalid_size_buffer.data()), static_cast<std::streamsize>(invalid_size_buffer.size()));

    Uint64Sequence input_sequence;
    CHECK_THROWS_AS((ss >> input_sequence), std::logic_error);
}

}  // namespace silkworm::snapshots::rec_split::encoding
