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

#include "lcp_kasai.hpp"

namespace silkworm::snapshots::seg {

void lcp_kasai(const uint8_t* data, const int* sa, const int* inv, int* lcp, int n) {
    struct DataPosComparator {
        const uint8_t* data;
        inline bool has_same_chars(int i, int j) const {
            return data[i] == data[j];
        }
    } comparator{data};

    lcp_kasai<DataPosComparator>(comparator, sa, inv, lcp, n);
}

}  // namespace silkworm::snapshots::seg
