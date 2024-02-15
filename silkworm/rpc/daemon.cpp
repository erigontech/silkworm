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

#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/rpc/common/compatibility.hpp>
#include <silkworm/rpc/ethbackend/remote_backend.hpp>
#include <silkworm/rpc/ethdb/file/local_database.hpp>
#include <silkworm/rpc/ethdb/kv/remote_database.hpp>
#include <silkworm/rpc/http/jwt.hpp>
#include <silkworm/rpc/json_rpc/validator.hpp>

namespace silkworm::rpc {

//! The maximum receive message in bytes for gRPC channels.
constexpr auto kRpcMaxReceiveMessageSize{64 * 1024 * 1024};  // 64 MiB

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
    int status{0};
    return abi::__cxa_demangle(abi::__cxa_current_exception_type()->name(), nullptr, nullptr, &status);
#endif
}

int Daemon::run(const DaemonSettings& settings, const DaemonInfo& info) {
    const bool are_settings_valid{validate_settings(settings)};
    if (!are_settings_valid) {
        return -1;
    }
    auto& log_settings = settings.log_settings;
    auto& context_pool_settings = settings.context_pool_settings;

    log::init(log_settings);
    log::set_thread_name("main-thread");

    auto mdbx_ver{mdbx::get_version()};
    auto mdbx_bld{mdbx::get_build()};
    SILK_INFO << "Silkrpc build info: " << info.build << " " << info.libraries;
    SILK_INFO << "Silkrpc libmdbx version: " << mdbx_ver.git.describe << " build: " << mdbx_bld.target << " compiler: " << mdbx_bld.compiler;

    std::set_terminate([]() {
        try {
            auto exc = std::current_exception();
            if (exc) {
                std::rethrow_exception(exc);
            }
        } catch (const std::exception& e) {
            SILK_CRIT << "Silkrpc terminating due to exception: " << e.what();
        } catch (...) {
            SILK_CRIT << "Silkrpc terminating due to unexpected exception: " << current_exception_name();
        }
        std::abort();
    });

    const auto pid = boost::this_process::get_id();
    const auto tid = std::this_thread::get_id();

    try {
        if (!settings.datadir) {
            SILK_INFO << "Silkrpc launched with private address " << settings.private_api_addr << " using "
                      << context_pool_settings.num_contexts << " contexts, " << settings.num_workers << " workers";
        } else {
            SILK_INFO << "Silkrpc launched with datadir " << *settings.datadir << " using "
                      << context_pool_settings.num_contexts << " contexts, " << settings.num_workers << " workers";
        }

        // Activate the local chaindata and snapshot access (if required)
        std::optional<mdbx::env_managed> chaindata_env;
        std::unique_ptr<snapshots::SnapshotRepository> snapshot_repository;
        if (settings.datadir) {
            DataDirectory data_folder{*settings.datadir};

            // Create a new local chaindata environment
            chaindata_env = std::make_optional<mdbx::env_managed>();
            silkworm::db::EnvConfig db_config{
                .path = data_folder.chaindata().path().string(),
                .in_memory = true,
                .shared = true,
                .max_readers = kDatabaseMaxReaders};
            *chaindata_env = silkworm::db::open_env(db_config);

            // Create a new snapshot repository
            snapshots::SnapshotSettings snapshot_settings{
                .repository_dir = data_folder.snapshots().path(),
            };
            snapshot_repository = std::make_unique<snapshots::SnapshotRepository>(std::move(snapshot_settings));
            snapshot_repository->reopen_folder();

            db::DataModel::set_snapshot_repository(snapshot_repository.get());
        }

        // Create the one-and-only Silkrpc daemon
        Daemon rpc_daemon{settings, chaindata_env};

        // Check protocol version compatibility with Core Services
        if (not settings.skip_protocol_check) {
            SILK_INFO << "Checking protocol version compatibility with core services...";

            const auto checklist = rpc_daemon.run_checklist();
            for (const auto& protocol_check : checklist.protocol_checklist) {
                SILK_INFO << protocol_check.result;
            }
            checklist.success_or_throw();
        } else {
            SILK_INFO << "Skip protocol version compatibility check with core services";
        }

        // Start execution context dedicated to handling termination signals
        boost::asio::io_context signal_context;
        boost::asio::signal_set signals{signal_context, SIGINT, SIGTERM};
        SILK_DEBUG << "Signals registered on signal_context " << &signal_context;
        signals.async_wait([&](const boost::system::error_code& error, int signal_number) {
            if (signal_number == SIGINT) std::cout << "\n";
            SILK_INFO << "Signal number: " << signal_number << " caught, error: " << error.message();
            rpc_daemon.stop();
        });

        SILK_INFO << "Starting ETH RPC API at " << settings.eth_end_point << " ENGINE RPC API at " << settings.engine_end_point;

        rpc_daemon.start();

        SILK_LOG << "Silkrpc is now running [pid=" << pid << ", main thread=" << tid << "]";

        signal_context.run();

        rpc_daemon.join();
    } catch (const std::exception& e) {
        SILK_CRIT << "Exception: " << e.what();
    } catch (...) {
        SILK_CRIT << "Unexpected exception: " << current_exception_name();
    }

    SILK_LOG << "Silkrpc exiting [pid=" << pid << ", main thread=" << tid << "]";

    return 0;
}

bool Daemon::validate_settings(const DaemonSettings& settings) {
    if (!settings.datadir && settings.private_api_addr.empty()) {
        SILK_ERROR << "Parameters datadir and private_api_addr cannot be both empty, specify one of them";
        SILK_ERROR << "Use --datadir or --private_api_addr flag to specify the path of database or the location of running instance";
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
        return grpc::CreateCustomChannel(settings.private_api_addr, grpc::InsecureChannelCredentials(), channel_args);
    };
}

Daemon::Daemon(DaemonSettings settings, std::optional<mdbx::env> chaindata_env)
    : settings_(std::move(settings)),
      create_channel_{make_channel_factory(settings_)},
      context_pool_{settings_.context_pool_settings.num_contexts},
      worker_pool_{settings_.num_workers},
      kv_stub_{::remote::KV::NewStub(create_channel_())} {
    // Load the channel authentication token (if required)
    if (settings_.jwt_secret_file) {
        jwt_secret_ = load_jwt_token(*settings_.jwt_secret_file);
    }

    if (chaindata_env) {
        // Use the existing chaindata environment
        chaindata_env_ = std::move(chaindata_env);
    }

    // Create private and shared state in execution contexts
    add_private_services();
    add_shared_services();

    // Create the unique KV state-changes stream feeding the state cache
    auto& context = context_pool_.next_context();
    state_changes_stream_ = std::make_unique<ethdb::kv::StateChangesStream>(context, kv_stub_.get());

    // Set compatibility with Erigon RpcDaemon at JSON RPC level
    compatibility::set_erigon_json_api_compatibility_required(settings_.erigon_json_rpc_compatibility);

    // Load JSON RPC specification for Ethereum API
    rpc::json_rpc::JsonRpcValidator::load_specification();
}

void Daemon::add_private_services() {
    auto grpc_channel = create_channel_();

    // Add the private state to each execution context
    for (std::size_t i{0}; i < settings_.context_pool_settings.num_contexts; ++i) {
        auto& context = context_pool_.next_context();
        auto& io_context{*context.io_context()};
        auto& grpc_context{*context.grpc_context()};

        std::unique_ptr<ethdb::Database> database;
        if (chaindata_env_) {
            database = std::make_unique<ethdb::file::LocalDatabase>(*chaindata_env_);
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
    for (std::size_t i{0}; i < settings_.context_pool_settings.num_contexts; ++i) {
        auto& io_context = context_pool_.next_io_context();

        add_shared_service(io_context, block_cache);
        add_shared_service<ethdb::kv::StateCache>(io_context, state_cache);
        add_shared_service(io_context, filter_storage);
    }
}

void Daemon::add_backend_services(std::vector<std::unique_ptr<ethbackend::BackEnd>>&& backends) {
    ensure(backends.size() == settings_.context_pool_settings.num_contexts,
           "Daemon::add_backend_service: number of backends must be equal to the number of contexts");

    // Add the BackEnd state to each execution context
    for (std::size_t i{0}; i < settings_.context_pool_settings.num_contexts; ++i) {
        auto& io_context = context_pool_.next_io_context();
        add_private_service<rpc::ethbackend::BackEnd>(io_context, std::move(backends[i]));
    }
}

DaemonChecklist Daemon::run_checklist() {
    const auto core_service_channel{create_channel_()};

    const auto kv_protocol_check{wait_for_kv_protocol_check(core_service_channel)};
    const auto ethbackend_protocol_check{wait_for_ethbackend_protocol_check(core_service_channel)};
    const auto mining_protocol_check{wait_for_mining_protocol_check(core_service_channel)};
    const auto txpool_protocol_check{wait_for_txpool_protocol_check(core_service_channel)};
    DaemonChecklist checklist{{kv_protocol_check, ethbackend_protocol_check, mining_protocol_check, txpool_protocol_check}};
    return checklist;
}

void Daemon::start() {
    auto make_rpc_server = [this](const std::string& end_point,
                                  const std::string& api_spec,
                                  boost::asio::io_context& ioc,
                                  std::optional<std::string> jwt_secret,
                                  InterfaceLogSettings ilog_settings) {
        return std::make_unique<http::Server>(
            end_point, api_spec, ioc, worker_pool_, settings_.cors_domain, std::move(jwt_secret),
            settings_.use_websocket, settings_.ws_compression, std::move(ilog_settings));
    };

    // Put the interface logs into the data folder in case we run with local data
    if (settings_.datadir) {
        std::filesystem::path logs_folder{*settings_.datadir / "logs"};
        settings_.eth_ifc_log_settings.container_folder = logs_folder.string();
        settings_.engine_ifc_log_settings.container_folder = logs_folder.string();
    }

    // Create and start the configured RPC services for each execution context
    for (std::size_t i{0}; i < settings_.context_pool_settings.num_contexts; ++i) {
        auto& ioc = context_pool_.next_io_context();

        if (!settings_.eth_end_point.empty()) {
            // ETH RPC API accepts customized namespaces and does not support JWT authentication
            rpc_services_.emplace_back(make_rpc_server(
                settings_.eth_end_point, settings_.eth_api_spec, ioc, /*jwt_secret=*/std::nullopt, settings_.eth_ifc_log_settings));
        }
        if (!settings_.engine_end_point.empty()) {
            // Engine RPC API has fixed namespaces and supports JWT authentication
            rpc_services_.emplace_back(make_rpc_server(
                settings_.engine_end_point, kDefaultEth2ApiSpec, ioc, jwt_secret_, settings_.engine_ifc_log_settings));
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
