#include "decoding_err.hpp"

#include <magic_enum.hpp>

namespace silkworm {

DecodingError::DecodingError(DecodingResult err, const std::string& message)
    : std::runtime_error{
          message.empty() ? "Decoding error : " + std::string{magic_enum::enum_name<DecodingResult>(err)}
                          : message},
      err_{err} {}

}  // namespace silkworm
