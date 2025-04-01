/*
   Copyright 2023 The Silkworm Authors

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

#include "error.hpp"

#include <iomanip>
#include <sstream>

#include <silkworm/core/common/util.hpp>

namespace silkworm::rpc {

std::ostream& operator<<(std::ostream& out, const Error& error) {
    out << error.to_string();
    return out;
}

std::string Error::to_string() const {
    const auto& error = *this;
    std::stringstream out;

    out << " code: " << error.code << " message: " << error.message;
    return out.str();
}

std::ostream& operator<<(std::ostream& out, const RevertError& error) {
    out << error.to_string();
    return out;
}

std::string RevertError::to_string() const {
    const auto& error = *this;
    std::stringstream out;

    out << " code: " << error.code << " message: " << error.message << " data: " << silkworm::to_hex(error.data);
    return out.str();
}

}  // namespace silkworm::rpc
