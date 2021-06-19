/*
   Copyright 2021 The Silkworm Authors

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

#include "mdbx.hpp"

namespace silkworm::db {

void EnvConfig::set_readonly(bool value) {
    if (value) {
        flags |= MDBX_RDONLY;
    } else {
        flags &= ~MDBX_RDONLY;
    }
}

void EnvConfig::set_exclusive(bool value) {
    if (value) {
        flags |= MDBX_EXCLUSIVE;
    } else {
        flags &= ~MDBX_EXCLUSIVE;
    }
}

::mdbx::env_managed open_env(const EnvConfig& config) {

    if (config.path.empty()) {
        throw std::invalid_argument("Invalid argument : config.path");
    }

    ::mdbx::env_managed::create_parameters cp{};  // Default create parameters
    ::mdbx::env::operate_parameters op{};         // Operational parameters

    op.mode = op.mode_from_flags(static_cast<MDBX_env_flags_t>(config.flags));
    op.options = op.options_from_flags(static_cast<MDBX_env_flags_t>(config.flags));
    op.durability = op.durability_from_flags(static_cast<MDBX_env_flags_t>(config.flags));
    op.max_maps = config.max_tables;
    op.max_readers = config.max_readers;

    return ::mdbx::env_managed{config.path, cp, op, (config.flags & MDBX_ACCEDE ? true : false)};
}

::mdbx::map_handle open_map(::mdbx::txn& tx, const MapConfig& config) {
    return tx.create_map(config.name, config.key_mode, config.value_mode);
}

::mdbx::cursor_managed open_cursor(::mdbx::txn& tx, const MapConfig& config) {
    return tx.open_cursor(open_map(tx, config));
}

}  // namespace silkworm::mdbx
