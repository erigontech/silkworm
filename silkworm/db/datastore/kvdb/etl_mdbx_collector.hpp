// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/datastore/etl/collector.hpp>

#include "mdbx.hpp"

namespace silkworm::datastore::kvdb {

// Function pointer to process Load on before Load data into tables
using LoadFunc = std::function<void(const datastore::etl::Entry&, RWCursorDupSort&, MDBX_put_flags_t)>;

class Collector : public datastore::etl::Collector {
  public:
    using datastore::etl::Collector::Collector;

    //! \brief Loads and optionally transforms collected entries into db
    //! \param [in] target : a cursor opened on target table and owned by caller (can be empty)
    //! \param [in] load_func : Pointer to function transforming collected entries. If NULL no transform is executed
    //! \param [in] flags : Optional put flags for append or upsert (default) items
    void load(
        RWCursorDupSort& target,
        const LoadFunc& load_func = {},
        MDBX_put_flags_t flags = MDBX_put_flags_t::MDBX_UPSERT) {
        datastore::etl::LoadFunc base_load_func = [&](const datastore::etl::Entry& etl_entry) {
            if (load_func) {
                load_func(etl_entry, target, flags);
            } else {
                mdbx::slice k = to_slice(etl_entry.key);
                if (etl_entry.value.empty()) {
                    target.erase(k);
                } else {
                    mdbx::slice v = to_slice(etl_entry.value);
                    mdbx::error::success_or_throw(target.put(k, &v, flags));
                }
            }
        };

        this->datastore::etl::Collector::load(base_load_func);
    }
};

}  // namespace silkworm::datastore::kvdb