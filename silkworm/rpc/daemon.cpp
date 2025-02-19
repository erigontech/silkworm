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
#include <boost/asio/version.hpp>
#include <boost/process/environment.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/kv/api/client.hpp>
#include <silkworm/db/kv/api/direct_client.hpp>
#include <silkworm/db/kv/grpc/client/remote_client.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/rpc/common/compatibility.hpp>
#include <silkworm/rpc/core/evm_executor.hpp>
#include <silkworm/rpc/engine/remote_execution_engine.hpp>
#include <silkworm/rpc/ethbackend/remote_backend.hpp>
#include <silkworm/rpc/ethdb/kv/backend_providers.hpp>
#include <silkworm/rpc/http/jwt.hpp>
#include <silkworm/rpc/json_rpc/request_handler.hpp>
#include <silkworm/rpc/json_rpc/validator.hpp>

namespace silkworm::rpc {

//! The maximum receive message in bytes for gRPC channels.
static constexpr int kRpcMaxReceiveMessageSize = 64 * 1024 * 1024;  // 64 MiB

//! The maximum number of concurrent readers allowed for MDBX datastore.
static constexpr int kDatabaseMaxReaders = 32000;

void DaemonChecklist::success_or_throw() const {
    for (const auto& protocol_check : protocol_checklist) {
        if (!protocol_check.compatible) {
            throw std::runtime_error{protocol_check.result};
        }
    }
}

static const char* current_exception_name() {
#ifdef WIN32
    return "<Exception name not supported on Windows>";
#else
    int status{0};
    return abi::__cxa_demangle(abi::__cxa_current_exception_type()->name(), nullptr, nullptr, &status);
#endif
}

//! Assemble the relevant library version information
static std::string get_library_versions() {
    std::string library_versions{"gRPC: "};
    library_versions.append(grpc::Version());
    library_versions.append(" Boost Asio: ");
    library_versions.append(std::to_string(BOOST_ASIO_VERSION));
    return library_versions;
}

int Daemon::run(const DaemonSettings& settings) {
    const bool are_settings_valid{validate_settings(settings)};
    if (!are_settings_valid) {
        return -1;
    }
    auto& log_settings = settings.log_settings;
    auto& context_pool_settings = settings.context_pool_settings;

    log::init(log_settings);
    log::set_thread_name("main-thread");

    const auto mdbx_ver{mdbx::get_version()};
    const auto mdbx_bld{mdbx::get_build()};
    SILK_INFO << "Silkrpc starting " << settings.build_info.build_description << " " << get_library_versions();
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
        std::optional<db::DataStore> data_store;
        if (settings.datadir) {
            DataDirectory data_dir{*settings.datadir};

            silkworm::datastore::kvdb::EnvConfig db_config{
                .path = data_dir.chaindata().path().string(),
                .readonly = true,
                .shared = true,
                .max_readers = kDatabaseMaxReaders};

            data_store.emplace(db::DataStore{
                db_config,
                data_dir.snapshots().path(),
            });

            // At startup check that chain configuration is valid
            datastore::kvdb::ROTxnManaged ro_txn = data_store->chaindata().access_ro().start_ro_tx();
            db::DataModel data_access = db::DataModelFactory{data_store->ref()}(ro_txn);
            if (const auto chain_config{data_access.read_chain_config()}; !chain_config) {
                throw std::runtime_error{"invalid chain configuration"};
            }
        }

        // Create the one-and-only Silkrpc daemon
        Daemon rpc_daemon{
            settings,
            data_store ? std::make_optional(data_store->ref()) : std::nullopt,
        };

        // Check protocol version compatibility with Core Services
        if (!settings.skip_protocol_check) {
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
        boost::asio::io_context shutdown_signal_ioc;
        boost::asio::signal_set shutdown_signal{shutdown_signal_ioc, SIGINT, SIGTERM};
        shutdown_signal.async_wait([&](const boost::system::error_code& error, int signal_number) {
            if (signal_number == SIGINT) std::cout << "\n";
            SILK_INFO << "Signal number: " << signal_number << " caught" << (error ? ", error: " + error.message() : "");
            rpc_daemon.stop();
        });

        SILK_INFO << "Starting ETH RPC API at " << settings.eth_end_point << " ENGINE RPC API at " << settings.engine_end_point;

        rpc_daemon.start();

        SILK_LOG << "Silkrpc is now running [pid=" << pid << ", main thread=" << tid << "]";

        shutdown_signal_ioc.run();

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

Daemon::Daemon(
    DaemonSettings settings,
    std::optional<db::DataStoreRef> data_store)
    : settings_(std::move(settings)),
      create_channel_{make_channel_factory(settings_)},
      context_pool_{settings_.context_pool_settings.num_contexts},
      worker_pool_{settings_.num_workers},
      data_store_{std::move(data_store)} {
    // Load the channel authentication token (if required)
    if (settings_.jwt_secret_file) {
        jwt_secret_ = load_jwt_token(*settings_.jwt_secret_file);
    }

    // Create shared and private state in execution contexts: order *matters* (e.g. for state cache)
    add_shared_services();
    add_private_services();
    EVMExecutor::register_service(worker_pool_);

    // Create the unique KV state-changes stream feeding the state cache
    auto& context = context_pool_.next_context();
    // TODO(canepat) should be /*remote=*/settings.standalone but we must fix state changes in db::kv::api::DirectClient mode
    state_changes_client_ = make_kv_client(context, /*remote=*/true);
    state_changes_stream_ = std::make_unique<db::kv::StateChangesStream>(context, *state_changes_client_);

    // Set compatibility with Erigon RpcDaemon at JSON RPC level
    compatibility::set_erigon_json_api_compatibility_required(settings_.erigon_json_rpc_compatibility);

    // Load JSON RPC specification for Ethereum API
    rpc::json_rpc::Validator::load_specification();
}

void Daemon::add_private_services() {
    auto grpc_channel = create_channel_();

    // Add the private state to each execution context
    for (size_t i{0}; i < settings_.context_pool_settings.num_contexts; ++i) {
        auto& context = context_pool_.next_context();
        auto& ioc = *context.ioc();
        auto& grpc_context{*context.grpc_context()};

        add_private_service<ethbackend::BackEnd>(ioc, std::make_unique<ethbackend::RemoteBackEnd>(grpc_channel, grpc_context));
        add_private_service<db::kv::api::Client>(ioc, make_kv_client(context, /*remote=*/!settings_.datadir));
        add_private_service(ioc, std::make_unique<txpool::TransactionPool>(grpc_channel, grpc_context));
        add_private_service(ioc, std::make_unique<txpool::Miner>(grpc_channel, grpc_context));
    }
}

void Daemon::add_shared_services() {
    // Create the unique block cache to be shared among the execution contexts
    auto block_cache = std::make_shared<BlockCache>();
    // Create the unique state cache to be shared among the execution contexts
    auto state_cache = std::make_shared<db::kv::api::CoherentStateCache>();
    // Create the unique filter storage to be shared among the execution contexts
    auto filter_storage = std::make_shared<FilterStorage>(context_pool_.size() * kDefaultFilterStorageSize);

    // Add the shared state to the execution contexts
    for (size_t i{0}; i < settings_.context_pool_settings.num_contexts; ++i) {
        auto& context = context_pool_.next_context();
        auto& ioc = *context.ioc();

        auto engine{std::make_shared<engine::RemoteExecutionEngine>(settings_.private_api_addr, *context.grpc_context())};

        add_shared_service(ioc, block_cache);
        add_shared_service<db::kv::api::StateCache>(ioc, std::move(state_cache));
        add_shared_service(ioc, filter_storage);
        add_shared_service<engine::ExecutionEngine>(ioc, std::move(engine));
    }
}

std::unique_ptr<db::kv::api::Client> Daemon::make_kv_client(rpc::ClientContext& context, bool remote) {
    auto& ioc = *context.ioc();
    auto& grpc_context = *context.grpc_context();
    auto* state_cache{must_use_shared_service<db::kv::api::StateCache>(ioc)};
    auto* backend{must_use_private_service<rpc::ethbackend::BackEnd>(ioc)};
    if (remote) {
        return std::make_unique<db::kv::grpc::client::RemoteClient>(
            create_channel_, grpc_context, state_cache, ethdb::kv::make_backend_providers(backend));
    }
    // TODO(canepat) finish implementation and clean-up composition of objects here
    db::kv::api::StateChangeRunner runner{ioc.get_executor()};
    db::kv::api::ServiceRouter router{runner.state_changes_calls_channel()};
    return std::make_unique<db::kv::api::DirectClient>(
        std::make_shared<db::kv::api::DirectService>(router, *data_store_, state_cache));
}

void Daemon::add_execution_services(const std::vector<std::shared_ptr<engine::ExecutionEngine>>& engines) {
    ensure(engines.size() == settings_.context_pool_settings.num_contexts,
           "Daemon::add_execution_services: number of execution engines must be equal to the number of contexts");

    // Add the Engine API execution service to each execution context
    for (size_t i{0}; i < settings_.context_pool_settings.num_contexts; ++i) {
        auto& ioc = context_pool_.next_ioc();
        add_shared_service<engine::ExecutionEngine>(ioc, engines[i]);
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
        commands::RpcApi rpc_api{ioc, worker_pool_, settings_.build_info};
        commands::RpcApiTable handler_table{api_spec};
        auto make_jsonrpc_handler = [rpc_api = std::move(rpc_api),
                                     handler_table = std::move(handler_table),
                                     ilog_settings = std::move(ilog_settings)](StreamWriter* stream_writer) mutable {
            return std::make_unique<json_rpc::RequestHandler>(stream_writer, rpc_api, handler_table, ilog_settings);
        };

        return std::make_unique<http::Server>(
            end_point, std::move(make_jsonrpc_handler), ioc, worker_pool_, settings_.cors_domain, std::move(jwt_secret),
            settings_.use_websocket, settings_.ws_compression, settings_.http_compression);
    };

    // Put the interface logs into the data folder
    std::filesystem::path data_folder{};
    if (data_store_) {
        datastore::kvdb::RWAccess chaindata = data_store_->chaindata.access_rw();
        mdbx::env& chaindata_env = *chaindata;
        auto chaindata_path = chaindata_env.get_path();
        // Trick to remove any empty filename because MDBX chaindata path ends with '/'
        if (chaindata_path.filename().empty()) {
            chaindata_path = chaindata_path.parent_path();
        }
        data_folder = chaindata_path.parent_path();
    }
    if (settings_.datadir) {
        data_folder = *settings_.datadir;
    }
    settings_.eth_ifc_log_settings.container_folder = data_folder / settings_.eth_ifc_log_settings.container_folder;
    settings_.engine_ifc_log_settings.container_folder = data_folder / settings_.engine_ifc_log_settings.container_folder;

    // Create and start the configured RPC services for each execution context
    for (size_t i{0}; i < settings_.context_pool_settings.num_contexts; ++i) {
        auto& ioc = context_pool_.next_ioc();

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
}

void Daemon::join() {
    context_pool_.join();
}

}  // namespace silkworm::rpc
