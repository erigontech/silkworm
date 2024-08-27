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

#pragma once

#include <ostream>

namespace silkworm::test_util {

//! Factory function creating one null output stream (all characters are discarded)
inline std::ostream& null_stream() {
    static struct NullBuf : public std::streambuf {
        int overflow(int c) override { return c; }
    } null_buf;
    static struct NullStream : public std::ostream {
        NullStream() : std::ostream(&null_buf) {}
    } null_strm;
    return null_strm;
}

}  // namespace silkworm::test_util
