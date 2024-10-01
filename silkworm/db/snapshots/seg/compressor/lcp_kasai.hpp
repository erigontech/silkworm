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

#include <concepts>
#include <cstdint>

namespace silkworm::snapshots::seg {

template <class TDataPosComparator>
    requires requires(const TDataPosComparator& data, int i, int j) {
        { data.has_same_chars(i, j) } -> std::same_as<bool>;
    }
void lcp_kasai(const TDataPosComparator& data, const int* sa, const int* inv, int* lcp, int n) {
    int k = 0;

    // Process all suffixes one by one starting from
    // first suffix in txt[]
    for (int i = 0; i < n; ++i) {
        // If the current suffix is at n-1, then we don’t
        // have next substring to consider. So lcp is not
        // defined for this substring, we put zero.
        if (inv[i] == n - 1) {
            k = 0;
            lcp[inv[i]] = 0;
            continue;
        }

        // j contains index of the next substring to
        // be considered  to compare with the present
        // substring, i.e. next string in suffix array.
        int j = sa[inv[i] + 1];

        // Directly start matching from k-th index as
        // at-least k-1 characters will match.
        while ((i + k < n) && (j + k < n) && data.has_same_chars(i + k, j + k)) {
            ++k;
        }

        // lcp for the present suffix.
        lcp[inv[i]] = k;

        // Deleting the starting character from the string.
        if (k > 0) {
            --k;
        }
    }
}

void lcp_kasai(const uint8_t* data, const int* sa, const int* inv, int* lcp, int n);

}  // namespace silkworm::snapshots::seg
