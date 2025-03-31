// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <silkworm/db/data_store.hpp>

namespace silkworm {

class HeaderChain;
class BodySequence;
class SentryClient;

class Message {
  public:
    virtual std::string name() const = 0;

    // execute: inbound message send a reply, outbound message send a request
    virtual void execute(db::DataStoreRef, HeaderChain&, BodySequence&, SentryClient&) = 0;

    virtual ~Message() = default;
};

}  // namespace silkworm
