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

#include "daemon.hpp"

#ifndef WIN32
#include <cxxabi.h>
#endif

#include <filesystem>
#include <stdexcept>

#include <boost/asio/signal_set.hpp>
#include <boost/process/environment.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/silkrpc/ethbackend/remote_backend.hpp>
#include <silkworm/silkrpc/ethdb/file/local_database.hpp>
#include <silkworm/silkrpc/ethdb/kv/remote_database.hpp>
#include <silkworm/silkrpc/http/jwt.hpp>

namespace silkworm::rpc {

//! The maximum receive message in bytes for gRPC channels.
constexpr auto kRpcMaxReceiveMessageSize{64 * 1024 * 1024};  // 64 MiB

//! The path to 'chaindata' folder relative to Silkworm data directory.
static constexpr const char kChaindataRelativePath[]{"/chaindata"};

//! The maximum number of concurrent readers allowed for MDBX datastore.
static constexpr const int kDatabaseMaxReaders{32000};

void DaemonChecklist::success_or_throw() const {
    for (const auto& protocol_check : protocol_checklist) {
        if (!protocol_check.compatible) {
            throw std::runtime_error{protocol_check.result};
        }
    }
}

const char* current_exception_name() {
#ifdef WIN32
    return "<Exception name not supported on Windows>";
#else
    int status;
    return abi::__cxa_demangle(abi::__cxa_current_exception_type()->name(), nullptr, nullptr, &status);
#endif
}

int Daemon::run(const DaemonSettings& settings, const DaemonInfo& info) {
    const bool are_settings_valid{validate_settings(settings)};
    if (!are_settings_valid) {
        return -1;
    }

    SILKRPC_LOG_VERBOSITY(settings.log_verbosity);
    SILKRPC_LOG_THREAD(true);

    auto mdbx_ver{mdbx::get_version()};
    auto mdbx_bld{mdbx::get_build()};
    SILKRPC_LOG << "Silkrpc build info: " << info.build << " " << info.libraries << "\n";
    SILKRPC_LOG << "Silkrpc libmdbx  version: " << mdbx_ver.git.describe << " build: " << mdbx_bld.target << " compiler: " << mdbx_bld.compiler << "\n";

    std::set_terminate([]() {
        try {
            auto exc = std::current_exception();
            if (exc) {
                std::rethrow_exception(exc);
            }
        } catch (const std::exception& e) {
            SILKRPC_CRIT << "Silkrpc terminating due to exception: " << e.what() << "\n";
        } catch (...) {
            SILKRPC_CRIT << "Silkrpc terminating due to unexpected exception: " << current_exception_name() << "\n";
        }
        std::abort();
    });

    const auto pid = boost::this_process::get_id();
    const auto tid = std::this_thread::get_id();

    try {
        if (!settings.datadir) {
            SILKRPC_LOG << "Silkrpc launched with target " << settings.target << " using " << settings.num_contexts
                        << " contexts, " << settings.num_workers << " workers\n";
        } else {
            SILKRPC_LOG << "Silkrpc launched with datadir " << *settings.datadir << " using " << settings.num_contexts
                        << " contexts, " << settings.num_workers << " workers\n";
        }

        // Create the one-and-only Silkrpc daemon
        Daemon rpc_daemon{settings};

        // Check protocol version compatibility with Core Services
        SILKRPC_LOG << "Checking protocol version compatibility with core services...\n";

        const auto checklist = rpc_daemon.run_checklist();
        for (const auto& protocol_check : checklist.protocol_checklist) {
            SILKRPC_LOG << protocol_check.result << "\n";
        }
        checklist.success_or_throw();

        // Start execution context dedicated to handling termination signals
        boost::asio::io_context signal_context;
        boost::asio::signal_set signals{signal_context, SIGINT, SIGTERM};
        SILKRPC_DEBUG << "Signals registered on signal_context " << &signal_context << "\n"
                      << std::flush;
        signals.async_wait([&](const boost::system::error_code& error, int signal_number) {
            if (signal_number == SIGINT) std::cout << "\n";
            SILKRPC_INFO << "Signal number: " << signal_number << " caught, error: " << error.message() << "\n"
                         << std::flush;
            rpc_daemon.stop();
        });

        SILKRPC_LOG << "Starting ETH RPC API at " << settings.http_port << " ENGINE RPC API at " << settings.engine_port << "\n";

        rpc_daemon.start();

        SILKRPC_LOG << "Silkrpc is now running [pid=" << pid << ", main thread=" << tid << "]\n";

        signal_context.run();

        rpc_daemon.join();
    } catch (const std::exception& e) {
        SILKRPC_CRIT << "Exception: " << e.what() << "\n";
    } catch (...) {
        SILKRPC_CRIT << "Unexpected exception: " << current_exception_name() << "\n";
    }

    SILKRPC_LOG << "Silkrpc exiting [pid=" << pid << ", main thread=" << tid << "]\n";

    return 0;
}

bool Daemon::validate_settings(const DaemonSettings& settings) {
    const auto datadir = settings.datadir;
    if (datadir && !std::filesystem::exists(*datadir)) {
        SILKRPC_ERROR << "Parameter datadir is invalid: [" << *datadir << "]\n";
        SILKRPC_ERROR << "Use --datadir flag to specify the path of Erigon database\n";
        return false;
    }

    const auto http_port = settings.http_port;
    if (!http_port.empty() && http_port.find(silkworm::kAddressPortSeparator) == std::string::npos) {
        SILKRPC_ERROR << "Parameter http_port is invalid: [" << http_port << "]\n";
        SILKRPC_ERROR << "Use --http_port flag to specify the local binding for Ethereum JSON RPC service\n";
        return false;
    }

    const auto engine_port = settings.engine_port;
    if (!engine_port.empty() && engine_port.find(silkworm::kAddressPortSeparator) == std::string::npos) {
        SILKRPC_ERROR << "Parameter engine_port is invalid: [" << engine_port << "]\n";
        SILKRPC_ERROR << "Use --engine_port flag to specify the local binding for Engine JSON RPC service\n";
        return false;
    }

    const auto target = settings.target;
    if (!target.empty() && target.find(':') == std::string::npos) {
        SILKRPC_ERROR << "Parameter target is invalid: [" << target << "]\n";
        SILKRPC_ERROR << "Use --target flag to specify the location of Erigon running instance\n";
        return false;
    }

    if (!datadir && target.empty()) {
        SILKRPC_ERROR << "Parameters datadir and target cannot be both empty, specify one of them\n";
        SILKRPC_ERROR << "Use --datadir or --target flag to specify the path or the location of Erigon instance\n";
        return false;
    }

    const auto api_spec = settings.api_spec;
    if (api_spec.empty()) {
        SILKRPC_ERROR << "Parameter api_spec is invalid: [" << api_spec << "]\n";
        SILKRPC_ERROR << "Use --api_spec flag to specify JSON RPC API namespaces as comma-separated list of strings\n";
        return false;
    }

    if (!settings.engine_port.empty() && !settings.jwt_secret_filename) {
        SILKRPC_ERROR << "Parameter jwt_secret_filename cannot be empty if engine_port is specified\n";
        SILKRPC_ERROR << "Use --jwt_secret_filename to specify the JWT token to use for Engine JSON RPC service\n";
        return false;
    }

    return true;
}

ChannelFactory Daemon::make_channel_factory(const DaemonSettings& settings) {
    return [&settings]() {
        grpc::ChannelArguments channel_args;
        // Allow to receive messages up to specified max size
        channel_args.SetMaxReceiveMessageSize(kRpcMaxReceiveMessageSize);
        // Allow each client to open its own TCP connection to server (sharing one single connection becomes a bottleneck under high load)
        channel_args.SetInt(GRPC_ARG_USE_LOCAL_SUBCHANNEL_POOL, 1);
        return grpc::CreateCustomChannel(settings.target, grpc::InsecureChannelCredentials(), channel_args);
    };
}

Daemon::Daemon(DaemonSettings settings)
    : settings_(std::move(settings)),
      create_channel_{make_channel_factory(settings_)},
      context_pool_{settings_.num_contexts},
      worker_pool_{settings_.num_workers},
      kv_stub_{::remote::KV::NewStub(create_channel_())} {
    // Load the channel authentication token (if required)
    if (settings.jwt_secret_filename) {
        std::string jwt_token;
        if (!load_jwt_token(*settings.jwt_secret_filename, jwt_token)) {
            std::string error_msg{"JWT token has wrong size: " + std::to_string(jwt_token.length())};
            SILKRPC_CRIT << error_msg << "\n";
            throw std::runtime_error{error_msg};
        }
        const auto jwt_token_bytes = silkworm::from_hex(jwt_token);
        if (!jwt_token_bytes) {
            std::string error_msg{"JWT token is incorrect: " + jwt_token};
            SILKRPC_CRIT << error_msg << "\n";
            throw std::runtime_error{error_msg};
        }
        jwt_secret_ = {jwt_token_bytes->cbegin(), jwt_token_bytes->cend()};
    }

    // Activate the local chaindata access (if required)
    if (settings_.datadir) {
        chaindata_env_ = std::make_shared<mdbx::env_managed>();
        std::string db_path = *settings_.datadir + kChaindataRelativePath;
        silkworm::db::EnvConfig db_config{
            .path = db_path,
            .in_memory = true,
            .shared = true,
            .max_readers = kDatabaseMaxReaders};
        *chaindata_env_ = silkworm::db::open_env(db_config);
    }

    // Create private and shared state in execution contexts
    add_private_services();
    add_shared_services();

    // Create the unique KV state-changes stream feeding the state cache
    auto& context = context_pool_.next_context();
    state_changes_stream_ = std::make_unique<ethdb::kv::StateChangesStream>(context, kv_stub_.get());
}

void Daemon::add_private_services() {
    auto grpc_channel = create_channel_();

    // Add the private state to each execution context
    for (std::size_t i{0}; i < settings_.num_contexts; ++i) {
        auto& context = context_pool_.next_context();
        auto& io_context{*context.io_context()};
        auto& grpc_context{*context.grpc_context()};

        std::unique_ptr<ethdb::Database> database;
        if (chaindata_env_) {
            database = std::make_unique<ethdb::file::LocalDatabase>(chaindata_env_);
        } else {
            database = std::make_unique<ethdb::kv::RemoteDatabase>(grpc_context, grpc_channel);
        }
        auto backend{std::make_unique<rpc::ethbackend::RemoteBackEnd>(io_context, grpc_channel, grpc_context)};
        auto tx_pool{std::make_unique<txpool::TransactionPool>(io_context, grpc_channel, grpc_context)};
        auto miner{std::make_unique<txpool::Miner>(io_context, grpc_channel, grpc_context)};

        add_private_service<ethdb::Database>(io_context, std::move(database));
        add_private_service<rpc::ethbackend::BackEnd>(io_context, std::move(backend));
        add_private_service(io_context, std::move(tx_pool));
        add_private_service(io_context, std::move(miner));
    }
}

void Daemon::add_shared_services() {
    // Create the unique block cache to be shared among the execution contexts
    auto block_cache = std::make_shared<BlockCache>();
    // Create the unique state cache to be shared among the execution contexts
    auto state_cache = std::make_shared<ethdb::kv::CoherentStateCache>();
    // Create the unique filter storage to be shared among the execution contexts
    auto filter_storage = std::make_shared<FilterStorage>(context_pool_.num_contexts() * kDefaultFilterStorageSize);

    // Add the shared state to the execution contexts
    for (std::size_t i{0}; i < settings_.num_contexts; ++i) {
        auto& io_context = context_pool_.next_io_context();

        add_shared_service(io_context, block_cache);
        add_shared_service<ethdb::kv::StateCache>(io_context, state_cache);
        add_shared_service(io_context, filter_storage);
    }
}

void Daemon::add_backend_service(std::unique_ptr<ethbackend::BackEnd>&& backend) {
    // Add the BackEnd state to each execution context
    for (std::size_t i{0}; i < settings_.num_contexts; ++i) {
        auto& io_context = context_pool_.next_io_context();
        add_private_service<rpc::ethbackend::BackEnd>(io_context, std::move(backend));
    }
}

DaemonChecklist Daemon::run_checklist() {
    const auto core_service_channel{create_channel_()};

    if (!settings_.datadir) {
        const auto kv_protocol_check{wait_for_kv_protocol_check(core_service_channel)};
        const auto ethbackend_protocol_check{wait_for_ethbackend_protocol_check(core_service_channel)};
        const auto mining_protocol_check{wait_for_mining_protocol_check(core_service_channel)};
        const auto txpool_protocol_check{wait_for_txpool_protocol_check(core_service_channel)};
        DaemonChecklist checklist{{kv_protocol_check, ethbackend_protocol_check, mining_protocol_check, txpool_protocol_check}};
        return checklist;
    } else {
        const auto ethbackend_protocol_check{wait_for_ethbackend_protocol_check(core_service_channel)};
        const auto mining_protocol_check{wait_for_mining_protocol_check(core_service_channel)};
        const auto txpool_protocol_check{wait_for_txpool_protocol_check(core_service_channel)};
        DaemonChecklist checklist{{ethbackend_protocol_check, mining_protocol_check, txpool_protocol_check}};
        return checklist;
    }
}

void Daemon::start() {
    for (std::size_t i{0}; i < settings_.num_contexts; ++i) {
        auto& ioc = context_pool_.next_io_context();

        if (not settings_.http_port.empty()) {
            rpc_services_.emplace_back(
                std::make_unique<http::Server>(
                    settings_.http_port, settings_.api_spec, ioc, worker_pool_, /*jwt_secret=*/std::nullopt));
        }
        if (not settings_.engine_port.empty()) {
            rpc_services_.emplace_back(
                std::make_unique<http::Server>(
                    settings_.engine_port, kDefaultEth2ApiSpec, ioc, worker_pool_, jwt_secret_));
        }
    }

    for (auto& service : rpc_services_) {
        service->start();
    }

    // Open the KV state-changes stream feeding the state cache
    state_changes_stream_->open();

    context_pool_.start();
}

void Daemon::stop() {
    // Cancel registration for incoming KV state changes
    state_changes_stream_->close();

    context_pool_.stop();

    for (auto& service : rpc_services_) {
        service->stop();
    }
}

void Daemon::join() {
    context_pool_.join();
}

}  // namespace silkworm::rpc
