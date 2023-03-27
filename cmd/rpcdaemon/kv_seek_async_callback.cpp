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
#include <functional>
#include <iomanip>
#include <iostream>

#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/core/common/util.hpp>
#include <silkworm/interfaces/remote/kv.grpc.pb.h>
#include <silkworm/silkrpc/common/util.hpp>

class GrpcKvCallbackReactor final : public grpc::ClientBidiReactor<remote::Cursor, remote::Pair> {
  public:
    explicit GrpcKvCallbackReactor(remote::KV::Stub& stub, std::chrono::milliseconds timeout) : stub_(stub) {
        context_.set_deadline(std::chrono::system_clock::now() + timeout);
        stub_.experimental_async()->Tx(&context_, this);
        StartCall();
    }

    void read_start(std::function<void(bool, remote::Pair)> read_completed) {
        read_completed_ = read_completed;
        StartRead(&pair_);
    }

    void write_start(remote::Cursor* cursor, std::function<void(bool)> write_completed) {
        write_completed_ = write_completed;
        StartWrite(cursor);
    }

    void OnReadDone(bool ok) override {
        read_completed_(ok, pair_);
    }

    void OnWriteDone(bool ok) override {
        write_completed_(ok);
    }

  private:
    remote::KV::Stub& stub_;
    grpc::ClientContext context_;
    remote::Pair pair_;
    std::function<void(bool, remote::Pair)> read_completed_;
    std::function<void(bool)> write_completed_;
};

int kv_seek_async_callback(const std::string& target, const std::string& table_name, const silkworm::Bytes& key, uint32_t timeout) {
    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{context.get_executor()};

    const auto channel = grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
    auto stub = remote::KV::NewStub(channel);

    boost::asio::signal_set signals(context, SIGINT, SIGTERM);
    signals.async_wait([&](const boost::system::error_code& error, int signal_number) {
        std::cout << "Signal caught, error: " << error.message() << " number: " << signal_number << std::endl
                  << std::flush;
        context.stop();
    });

    GrpcKvCallbackReactor reactor{*stub, std::chrono::milliseconds{timeout}};

    std::cout << "KV Tx START\n";
    reactor.read_start([&](bool txid_read_ok, const remote::Pair& txid_pair) {
        if (!txid_read_ok) {
            std::cout << "KV Tx error reading TXID" << std::flush;
            return;
        }
        const auto tx_id = txid_pair.cursorid();
        std::cout << "KV Tx START <- txid: " << tx_id << "\n";
        auto open_message = remote::Cursor{};
        open_message.set_op(remote::Op::OPEN);
        open_message.set_bucketname(table_name);
        reactor.write_start(&open_message, [&](bool open_write_ok) {
            if (!open_write_ok) {
                std::cout << "error writing OPEN gRPC" << std::flush;
                return;
            }
            std::cout << "KV Tx OPEN -> table_name: " << table_name << "\n";
            reactor.read_start([&](bool open_read_ok, const remote::Pair& open_pair) {
                if (!open_read_ok) {
                    std::cout << "error reading OPEN gRPC" << std::flush;
                    return;
                }
                const auto cursor_id = open_pair.cursorid();
                std::cout << "KV Tx OPEN <- cursor: " << cursor_id << "\n";
                auto seek_message = remote::Cursor{};
                seek_message.set_op(remote::Op::SEEK);
                seek_message.set_cursor(cursor_id);
                seek_message.set_k(key.c_str(), key.length());
                reactor.write_start(&seek_message, [&, cursor_id](bool seek_write_ok) {
                    if (!seek_write_ok) {
                        std::cout << "error writing SEEK gRPC" << std::flush;
                        return;
                    }
                    std::cout << "KV Tx SEEK -> cursor: " << cursor_id << " key: " << key << "\n";
                    reactor.read_start([&, cursor_id](bool seek_read_ok, const remote::Pair& seek_pair) {
                        if (!seek_read_ok) {
                            std::cout << "error reading SEEK gRPC" << std::flush;
                            return;
                        }
                        const auto& key_bytes = silkworm::byte_view_of_string(seek_pair.k());
                        const auto& value_bytes = silkworm::byte_view_of_string(seek_pair.v());
                        std::cout << "KV Tx SEEK <- key: " << key_bytes << " value: " << value_bytes << std::endl;
                        auto close_message = remote::Cursor{};
                        close_message.set_op(remote::Op::CLOSE);
                        close_message.set_cursor(cursor_id);
                        reactor.write_start(&close_message, [&, cursor_id](bool close_write_ok) {
                            if (!close_write_ok) {
                                std::cout << "error writing CLOSE gRPC" << std::flush;
                                return;
                            }
                            std::cout << "KV Tx CLOSE -> cursor: " << cursor_id << "\n";
                            reactor.read_start([&](bool close_read_ok, const remote::Pair& close_pair) {
                                if (!close_read_ok) {
                                    std::cout << "error reading CLOSE gRPC" << std::flush;
                                    return;
                                }
                                std::cout << "KV Tx CLOSE <- cursor: " << close_pair.cursorid() << "\n";
                                context.stop();
                            });
                        });
                    });
                });
            });
        });
    });

    context.run();

    return 0;
}
