/*
   Copyright 2024 The Silkworm Authors

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

#include "elias_fano_decoder.hpp"

#include <sstream>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>

namespace silkworm::snapshots::elias_fano {

TEST_CASE("EliasFanoDecoder") {
    EliasFanoList32Builder expected_list{3, 3};
    expected_list.add_offset(1);
    expected_list.add_offset(2);
    expected_list.add_offset(3);
    expected_list.build();
    std::stringstream expected_list_stream;
    expected_list_stream << expected_list;
    const auto expected_list_str = expected_list_stream.str();

    EliasFanoDecoder decoder;
    decoder.decode_word(string_view_to_byte_view(expected_list_str));
    CHECK(decoder.value == expected_list.as_view());
}

}  // namespace silkworm::snapshots::elias_fano
