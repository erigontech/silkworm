/*
   Copyright 2020 The Silkworm Authors

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

#include "common.hpp"

#include <boost/algorithm/hex.hpp>

namespace silkworm::eth {

Address HexToAddress(std::string_view hex) {
  Address a;
  a.fill(0);
  static constexpr size_t kMaxNibbles = 2 * kAddressLength;
  if (hex.length() <= kMaxNibbles) {
    boost::algorithm::unhex(hex.begin(), hex.end(), a.begin());
  } else {
    boost::algorithm::unhex(hex.begin(), hex.begin() + kMaxNibbles, a.begin());
  }
  return a;
}

}  // namespace silkworm::eth