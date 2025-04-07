// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <ostream>
#include <string>

#include "message.hpp"

namespace silkworm {

class InboundMessage : public Message {
  public:
    virtual uint64_t req_id() const = 0;
    virtual std::string content() const = 0;
    virtual std::string to_string() const;
};

std::ostream& operator<<(std::ostream&, const silkworm::InboundMessage&);
std::string identify(const silkworm::InboundMessage& message);

}  // namespace silkworm
