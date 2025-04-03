// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>

namespace silkworm::rpc {

//! The callback to activate reading each event from the gRPC completion queue.
using TagProcessor = std::function<void(bool)>;

//! This represents the completion event (better known as TAG in gRPC) of any async operation.
//! By packing the tag information this way, each tag knows how to process itself.
struct CompletionTag {
    TagProcessor* processor{nullptr};  // The function to be called to process incoming event
    bool ok{false};                    // The result of tag processing as indicated by gRPC library (name consistent with gRPC examples)
};

}  // namespace silkworm::rpc
