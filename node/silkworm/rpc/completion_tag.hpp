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

#ifndef SILKWORM_RPC_COMPLETION_TAG_HPP_
#define SILKWORM_RPC_COMPLETION_TAG_HPP_

namespace silkworm::rpc {

//! The callback to activate reading each event from the gRPC completion queue.
using TagProcessor = std::function<void(bool)>;

//! This represents the completion event (better known as TAG in gRPC) of any async operation.
/// By packing the tag information this way, each tag knows how to process itself.
struct CompletionTag {
    TagProcessor* processor{nullptr}; // The function to be called to process incoming event
    bool ok{false}; // The result of tag processing as indicated by gRPC library (name consistent with gRPC examples)
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_COMPLETION_TAG_HPP_
