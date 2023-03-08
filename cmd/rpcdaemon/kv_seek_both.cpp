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

#include <iomanip>
#include <iostream>
#include <string>

#include <grpcpp/grpcpp.h>
#include <silkworm/core/common/util.hpp>

#include <silkworm/interfaces/remote/kv.grpc.pb.h>

#include <silkworm/silkrpc/common/constants.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/grpc/util.hpp>

int kv_seek_both(const std::string& target, const std::string& table_name, const silkworm::Bytes& key, const silkworm::Bytes& subkey) {
    // Create KV stub using insecure channel to target
    grpc::ClientContext context;

    const auto channel = grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
    const auto stub = remote::KV::NewStub(channel);
    const auto reader_writer = stub->Tx(&context);
    std::cout << "KV Tx START\n";

    // Read TX identifier
    auto txid_pair = remote::Pair{};
    auto success = reader_writer->Read(&txid_pair);
    if (!success) {
        std::cerr << "KV stream closed receiving TXID\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    const auto tx_id = txid_pair.cursorid();
    std::cout << "KV Tx START <- txid: " << tx_id << "\n";

    // Open cursor
    auto open_message = remote::Cursor{};
    open_message.set_op(remote::Op::OPEN);
    open_message.set_bucketname(table_name);
    success = reader_writer->Write(open_message);
    if (!success) {
        std::cerr << "KV stream closed sending OPEN operation req\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    std::cout << "KV Tx OPEN -> table_name: " << table_name << "\n";
    auto open_pair = remote::Pair{};
    success = reader_writer->Read(&open_pair);
    if (!success) {
        std::cerr << "KV stream closed receiving OPEN operation rsp\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    auto cursor_id = open_pair.cursorid();
    std::cout << "KV Tx OPEN <- cursor: " << cursor_id << "\n";

    // Seek given key in given table
    auto seek_both_message = remote::Cursor{};
    seek_both_message.set_op(remote::Op::SEEK_BOTH);
    seek_both_message.set_cursor(cursor_id);
    seek_both_message.set_k(key.c_str(), key.length());
    seek_both_message.set_v(subkey.c_str(), subkey.length());
    success = reader_writer->Write(seek_both_message);
    if (!success) {
        std::cerr << "KV stream closed sending SEEK_BOTH operation req\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    std::cout << "KV Tx SEEK_BOTH -> cursor: " << cursor_id << " key: " << key << " subkey: " << subkey << "\n";
    auto seek_both_pair = remote::Pair{};
    success = reader_writer->Read(&seek_both_pair);
    if (!success) {
        std::cerr << "KV stream closed receiving SEEK_BOTH operation rsp\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    const auto& rsp_key = silkworm::byte_view_of_string(seek_both_pair.k());
    const auto& rsp_value = silkworm::byte_view_of_string(seek_both_pair.v());
    std::cout << "KV Tx SEEK_BOTH <- key: " << rsp_key << " value: " << rsp_value << std::endl;

    // Close cursor
    auto close_message = remote::Cursor{};
    close_message.set_op(remote::Op::CLOSE);
    close_message.set_cursor(cursor_id);
    success = reader_writer->Write(close_message);
    if (!success) {
        std::cerr << "KV stream closed sending CLOSE operation req\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    std::cout << "KV Tx CLOSE -> cursor: " << cursor_id << "\n";
    auto close_pair = remote::Pair{};
    success = reader_writer->Read(&close_pair);
    if (!success) {
        std::cerr << "KV stream closed receiving CLOSE operation rsp\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    std::cout << "KV Tx CLOSE <- cursor: " << close_pair.cursorid() << "\n";

    reader_writer->WritesDone();
    grpc::Status status = reader_writer->Finish();
    std::cout << "KV Tx STATUS: " << status << "\n";

    return 0;
}
