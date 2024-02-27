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

#include <silkworm/sentry/common/error.hpp>

namespace silkworm::sentry::rlpx::auth {

enum class EciesCipherErrorCode : uint8_t {
    kSharedSecretFailure = 1,
    kInvalidMAC,
    kDataSizeTooShort,
};

using EciesCipherError = sentry::Error<EciesCipherErrorCode>;

}  // namespace silkworm::sentry::rlpx::auth
