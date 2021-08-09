/*
   Copyright 2020-2021 The Silkworm Authors

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

#ifndef SILKWORM_TYPES_LOG_CBOR_HPP_
#define SILKWORM_TYPES_LOG_CBOR_HPP_

#include <silkworm/types/log.hpp>

namespace silkworm {

// Erigon-compatible CBOR encoding for storage.
// See core/types/log.go
Bytes cbor_encode(const std::vector<Log>& v);

}  // namespace silkworm

#endif  // SILKWORM_TYPES_LOG_CBOR_HPP_
