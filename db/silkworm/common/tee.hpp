/*
   Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_COMMON_TEE_HPP_
#define SILKWORM_COMMON_TEE_HPP_

#include <cstdio>
#include <ctime>
#include <fstream>
#include <iostream>
#include <streambuf>

namespace silkworm {

// Tee code adapted from http://wordaligned.org/articles/cpp-streambufs
class teebuf : public std::streambuf {
  public:
    // Construct a streambuf which tees output to the supplied streambufs.
    teebuf(std::streambuf* b1, std::streambuf* b2) : sb1(b1), sb2(b2) {}

    void set_streams(std::streambuf* b1, std::streambuf* b2) {
        sb1 = b1;
        sb2 = b2;
    }

  private:
    // This tee buffer has no buffer. So every character "overflows"
    // and can be put directly into the teed buffers.
    int overflow(int c) override {
        if (c == EOF) {
            return !EOF;
        } else {
            int const r1 = sb1->sputc(static_cast<char>(c));
            int const r2 = sb2->sputc(static_cast<char>(c));
            return (r1 == EOF || r2 == EOF) ? EOF : c;
        }
    }

    // Sync both teed buffers.
    int sync() override {
        int const r1 = sb1->pubsync();
        int const r2 = sb2->pubsync();
        return (r1 == 0 && r2 == 0) ? 0 : -1;
    }

    std::streambuf* sb1;
    std::streambuf* sb2;
};

class teestream : public std::ostream {
  public:
    // Construct an ostream which tees output to the supplied ostreams.
    teestream(std::ostream& o1, std::ostream& o2) : std::ostream(&tbuf), tbuf(o1.rdbuf(), o2.rdbuf()) {}

    void set_streams(std::streambuf* sb1, std::streambuf* sb2) { tbuf.set_streams(sb1, sb2); }

  private:
    teebuf tbuf;
};

}  // namespace silkworm

#endif  // SILKWORM_COMMON_TEE_HPP_
