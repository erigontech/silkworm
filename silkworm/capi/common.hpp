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

#include <filesystem>

#include <silkworm/infra/common/log.hpp>

#include "silkworm.h"

//! Build a file system path from its C null-terminated upper-bounded representation
std::filesystem::path parse_path(const char path[SILKWORM_PATH_SIZE]);

//! Build log configuration matching Erigon log format w/ custom verbosity level
silkworm::log::Settings make_log_settings(SilkwormLogLevel c_log_level);
