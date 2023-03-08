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

#include <chrono>
#include <iomanip>
#include <iostream>

#include <grpcpp/grpcpp.h>
#include <silkworm/core/common/util.hpp>

#include <silkworm/interfaces/remote/kv.grpc.pb.h>

#include <silkworm/silkrpc/common/constants.hpp>
#include <silkworm/silkrpc/common/util.hpp>

int kv_seek_async(const std::string& target, const std::string& table_name, const silkworm::Bytes& key, uint32_t timeout) {
    // Create KV stub using insecure channel to target
    grpc::ClientContext context;
    grpc::CompletionQueue queue;
    grpc::Status status;
    void * got_tag;
    bool ok;

    const auto channel = grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
    const auto stub = remote::KV::NewStub(channel);

    // Prepare RPC call context and stream
    context.set_deadline(std::chrono::system_clock::system_clock::now() + std::chrono::milliseconds{timeout});
    const auto reader_writer = stub->PrepareAsyncTx(&context, &queue);

    void* START_TAG  = reinterpret_cast<void *>(0);
    void* OPEN_TAG   = reinterpret_cast<void *>(1);
    void* SEEK_TAG   = reinterpret_cast<void *>(2);
    void* CLOSE_TAG  = reinterpret_cast<void *>(3);
    void* FINISH_TAG = reinterpret_cast<void *>(4);

    // 1) StartCall
    std::cout << "KV Tx START\n";
    // 1.1) StartCall + Next
    reader_writer->StartCall(START_TAG);
    bool has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != START_TAG) {
        return -1;
    }
    // 1.2) Read + Next
    auto txid_pair = remote::Pair{};
    reader_writer->Read(&txid_pair, START_TAG);
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != START_TAG) {
        return -1;
    }
    const auto tx_id = txid_pair.cursorid();
    std::cout << "KV Tx START <- txid: " << tx_id << "\n";

    // 2) Open cursor
    std::cout << "KV Tx OPEN -> table_name: " << table_name << "\n";
    // 2.1) Write + Next
    auto open_message = remote::Cursor{};
    open_message.set_op(remote::Op::OPEN);
    open_message.set_bucketname(table_name);
    reader_writer->Write(open_message, OPEN_TAG);
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != OPEN_TAG) {
        return -1;
    }
    // 2.2) Read + Next
    auto open_pair = remote::Pair{};
    reader_writer->Read(&open_pair, OPEN_TAG);
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != OPEN_TAG) {
        return -1;
    }
    auto cursor_id = open_pair.cursorid();
    std::cout << "KV Tx OPEN <- cursor: " << cursor_id << "\n";

    // 3) Seek given key in given table
    std::cout << "KV Tx SEEK -> cursor: " << cursor_id << " key: " << key << "\n";
    // 3.1) Write + Next
    auto seek_message = remote::Cursor{};
    seek_message.set_op(remote::Op::SEEK);
    seek_message.set_cursor(cursor_id);
    seek_message.set_k(key.c_str(), key.length());
    reader_writer->Write(seek_message, SEEK_TAG);
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != SEEK_TAG) {
        return -1;
    }
    // 3.2) Read + Next
    auto seek_pair = remote::Pair{};
    reader_writer->Read(&seek_pair, SEEK_TAG);
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != SEEK_TAG) {
        return -1;
    }
    const auto& key_bytes = silkworm::byte_view_of_string(seek_pair.k());
    const auto& value_bytes = silkworm::byte_view_of_string(seek_pair.v());
    std::cout << "KV Tx SEEK <- key: " << key_bytes << " value: " << value_bytes << std::endl;

    // 4) Close cursor
    std::cout << "KV Tx CLOSE -> cursor: " << cursor_id << "\n";
    // 4.1) Write + Next
    auto close_message = remote::Cursor{};
    close_message.set_op(remote::Op::CLOSE);
    close_message.set_cursor(cursor_id);
    reader_writer->Write(close_message, CLOSE_TAG);
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != CLOSE_TAG) {
        return -1;
    }
    // 4.2) Read + Next
    auto close_pair = remote::Pair{};
    reader_writer->Read(&close_pair, CLOSE_TAG);
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != CLOSE_TAG) {
        return -1;
    }
    std::cout << "KV Tx CLOSE <- cursor: " << close_pair.cursorid() << "\n";

    // 5) Finish
    reader_writer->Finish(&status, FINISH_TAG);
    if (!status.ok()) {
        std::cout << "KV Tx Status <- error_code: " << status.error_code() << "\n";
        std::cout << "KV Tx Status <- error_message: " << status.error_message() << "\n";
        std::cout << "KV Tx Status <- error_details: " << status.error_details() << "\n";
        return -1;
    }

    return 0;
}
