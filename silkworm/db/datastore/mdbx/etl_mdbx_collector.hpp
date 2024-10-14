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

#include <silkworm/db/datastore/etl/collector.hpp>

#include "mdbx.hpp"

namespace silkworm::db::etl_mdbx {

// Function pointer to process Load on before Load data into tables
using LoadFunc = std::function<void(const etl::Entry&, db::RWCursorDupSort&, MDBX_put_flags_t)>;

class Collector : public etl::Collector {
  public:
    using etl::Collector::Collector;

    //! \brief Loads and optionally transforms collected entries into db
    //! \param [in] target : a cursor opened on target table and owned by caller (can be empty)
    //! \param [in] load_func : Pointer to function transforming collected entries. If NULL no transform is executed
    //! \param [in] flags : Optional put flags for append or upsert (default) items
    void load(
        db::RWCursorDupSort& target,
        const LoadFunc& load_func = {},
        MDBX_put_flags_t flags = MDBX_put_flags_t::MDBX_UPSERT) {
        etl::LoadFunc base_load_func = [&](const etl::Entry& etl_entry) {
            if (load_func) {
                load_func(etl_entry, target, flags);
            } else {
                mdbx::slice k{db::to_slice(etl_entry.key)};
                if (etl_entry.value.empty()) {
                    target.erase(k);
                } else {
                    mdbx::slice v{db::to_slice(etl_entry.value)};
                    mdbx::error::success_or_throw(target.put(k, &v, flags));
                }
            }
        };

        this->etl::Collector::load(base_load_func);
    }
};

}  // namespace silkworm::db::etl_mdbx