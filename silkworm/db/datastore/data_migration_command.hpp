// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

namespace silkworm::datastore {

struct DataMigrationCommand {
    virtual ~DataMigrationCommand() = default;
    virtual std::string description() const = 0;
};

}  // namespace silkworm::datastore
