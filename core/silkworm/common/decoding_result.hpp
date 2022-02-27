/*
   Copyright 2022 The Silkworm Authors

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

#ifndef SILKWORM_COMMON_DECODING_RESULT_HPP_
#define SILKWORM_COMMON_DECODING_RESULT_HPP_

namespace silkworm {

// Error codes for RLP and other decoding
enum class [[nodiscard]] DecodingResult{
    kOk = 0,
    kOverflow,
    kLeadingZero,
    kInputTooShort,
    kNonCanonicalSize,
    kUnexpectedLength,
    kUnexpectedString,
    kUnexpectedList,
    kListLengthMismatch,
    kInvalidVInSignature,         // v != 27 && v != 28 && v < 35, see EIP-155
    kUnsupportedTransactionType,  // EIP-2718
    kInvalidFieldset,
};

}  // namespace silkworm

#endif  // SILKWORM_COMMON_DECODING_RESULT_HPP_
