// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/datastore/common/timestamp.hpp>

#include "../api/endpoint/common.hpp"
#include "../api/endpoint/temporal_range.hpp"

namespace silkworm::db::kv::api {

datastore::TimestampRange as_datastore_ts_range(TimestampRange ts_range, bool reverse);

}  // namespace silkworm::db::kv::api
