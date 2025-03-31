// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "lcp_kasai.hpp"

namespace silkworm::snapshots::seg {

void lcp_kasai(const uint8_t* data, const int* sa, const int* inv, int* lcp, int n) {
    struct DataPosComparator {
        const uint8_t* data;
        bool has_same_chars(int i, int j) const {
            return data[i] == data[j];
        }
    } comparator{data};

    lcp_kasai<DataPosComparator>(comparator, sa, inv, lcp, n);
}

}  // namespace silkworm::snapshots::seg
