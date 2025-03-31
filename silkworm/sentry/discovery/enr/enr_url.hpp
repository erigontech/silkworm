// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>
#include <string_view>

#include <silkworm/sentry/common/ecc_key_pair.hpp>

#include "enr_record.hpp"

namespace silkworm::sentry::discovery::enr {

struct EnrUrl {
    static EnrRecord parse(std::string_view url_str);
    static std::string make(const EnrRecord& record, const EccKeyPair& key_pair);
};

}  // namespace silkworm::sentry::discovery::enr
