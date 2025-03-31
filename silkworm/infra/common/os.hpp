// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>

//! Low-level OS utilities
namespace silkworm::os {

uint64_t max_file_descriptors();

bool set_max_file_descriptors(uint64_t max_descriptors);

size_t page_size() noexcept;

}  // namespace silkworm::os
