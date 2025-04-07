// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "client.hpp"

#include <algorithm>
#include <ctime>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include <libtorrent/alert_types.hpp>
#include <libtorrent/hex.hpp>
#include <libtorrent/magnet_uri.hpp>
#include <libtorrent/read_resume_data.hpp>
#include <libtorrent/write_resume_data.hpp>
#include <magic_enum.hpp>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>

#include "trackers.hpp"

namespace silkworm::snapshots::bittorrent {

namespace fs = std::filesystem;
using namespace std::chrono_literals;

std::vector<char> BitTorrentClient::load_file(const fs::path& filename) {
    if (!std::filesystem::exists(filename)) return {};
    std::ifstream input_file_stream{filename, std::ios::binary | std::ios::ate};
    input_file_stream.exceptions(std::ios::failbit | std::ios::badbit);
    std::streamsize file_size = input_file_stream.tellg();
    std::vector<char> contents(static_cast<size_t>(file_size));
    input_file_stream.seekg(0);
    input_file_stream.read(contents.data(), file_size);
    return contents;
}

void BitTorrentClient::save_file(const fs::path& filename, const std::vector<char>& data) {
    SILK_TRACE << "Save #data=" << data.size() << " in file: " << filename;
    std::ofstream output_file_stream{filename, std::ios::binary | std::ios::trunc};
    output_file_stream.exceptions(std::ios::failbit | std::ios::badbit);
    output_file_stream.write(data.data(), static_cast<std::streamsize>(data.size()));
}

BitTorrentClient::BitTorrentClient(BitTorrentSettings settings)
    : settings_(std::move(settings)),
      session_file_{settings_.repository_path / fs::path{kSessionFileName}},
      resume_dir_{settings_.repository_path / fs::path{kResumeDirName}},
      session_{load_or_create_session_parameters()} {
    SILK_TRACE << "BitTorrentClient::BitTorrentClient start";
    auto torrents_params = load_resume_data();
    for (auto& params : torrents_params) {
        session_.async_add_torrent(std::move(params));
    }
    last_save_resume_ = std::chrono::steady_clock::now();
    SILK_TRACE << "Torrents #total: " << torrents_params.size();
}

BitTorrentClient::~BitTorrentClient() {
    BitTorrentClient::stop();
}

void BitTorrentClient::add_info_hash(std::string_view name, std::string_view info_hash) {
    add_info_hash(name, info_hash, kBestTrackers);
}

void BitTorrentClient::add_info_hash(std::string_view name, std::string_view info_hash, std::vector<std::string> trackers) {
    lt::sha1_hash sha1_info_hash;
    lt::aux::from_hex(info_hash, sha1_info_hash.data());
    lt::info_hash_t info_hashes{sha1_info_hash};
    if (exists_resume_file(info_hashes)) {
        SILK_TRACE << "Resume file found: " << resume_file_path(info_hashes);
        return;
    }
    lt::add_torrent_params torrent;
    torrent.name = name;
    torrent.info_hashes = info_hashes;
    torrent.save_path = settings_.repository_path.string();
    torrent.trackers = std::move(trackers);
    session_.async_add_torrent(std::move(torrent));
    SILK_TRACE << "BitTorrentClient::add_info_hash: " << info_hash << " added";
}

void BitTorrentClient::add_torrent_info(std::shared_ptr<lt::torrent_info> info) {
    lt::add_torrent_params torrent;
    torrent.ti = std::move(info);
    torrent.save_path = settings_.repository_path.string();
    session_.async_add_torrent(std::move(torrent));
    SILK_TRACE << "BitTorrentClient::add_torrent_info added";
}

bool BitTorrentClient::stop() {
    SILK_TRACE << "BitTorrentClient::stop start";
    bool changed = ActiveComponent::stop();
    if (changed) {
        stop_condition_.notify_one();
    }
    SILK_TRACE << "BitTorrentClient::stop end";
    return changed;
}

lt::session_params BitTorrentClient::load_or_create_session_parameters() const {
    // Restore session parameters from old session, if any
    const auto prev_session_data = BitTorrentClient::load_file(session_file_);
    auto session_params =
        prev_session_data.empty() ? lt::session_params{} : lt::read_session_params(prev_session_data);

    // Customize the session settings
    auto& settings = session_params.settings;
    settings.set_int(lt::settings_pack::alert_mask,
                     lt::alert_category::error | lt::alert_category::storage |
                         lt::alert_category::status | lt::alert_category::performance_warning);
    settings.set_int(lt::settings_pack::download_rate_limit, settings_.download_rate_limit * int{1_Mebi});
    settings.set_int(lt::settings_pack::upload_rate_limit, settings_.upload_rate_limit * int{1_Mebi});
    settings.set_int(lt::settings_pack::active_downloads, settings_.active_downloads);
    settings.set_int(lt::settings_pack::max_out_request_queue, settings_.max_out_request_queue);
    settings.set_int(lt::settings_pack::aio_threads, settings_.aio_threads);
    settings.set_bool(lt::settings_pack::announce_to_all_tiers, settings_.announce_to_all_tiers);
    settings.set_bool(lt::settings_pack::enable_dht, false);

    return session_params;
}

std::vector<lt::add_torrent_params> BitTorrentClient::load_resume_data() const {
    fs::create_directories(settings_.repository_path);
    ensure(fs::exists(settings_.repository_path), "BitTorrentClient: repository path does not exist");
    ensure(fs::is_directory(settings_.repository_path), "BitTorrentClient: repository path is not a directory");
    SILK_TRACE << "Torrent repository folder: " << settings_.repository_path.string();

    fs::create_directories(resume_dir_);
    ensure(fs::exists(resume_dir_), "BitTorrentClient: resume path does not exist");
    ensure(fs::is_directory(resume_dir_), "BitTorrentClient: resume path is not a directory");
    SILK_TRACE << "Resume folder: " << resume_dir_;

    std::vector<lt::add_torrent_params> torrents_params;
    for (const auto& file : fs::directory_iterator{resume_dir_}) {
        if (!fs::is_regular_file(file.path()) || file.path().extension() != kResumeFileExt) {
            continue;
        }
        SILK_TRACE << "File path: " << file.path() << " name: " << file.path().filename();
        const auto resume_data = load_file(file.path().string());
        if (!resume_data.empty()) {
            auto params = lt::read_resume_data(resume_data);
            params.save_path = settings_.repository_path.string();
            torrents_params.push_back(std::move(params));
        }
    }
    SILK_TRACE << "Torrents #resumed: " << torrents_params.size();

    return torrents_params;
}

void BitTorrentClient::add_magnet_uri(const std::string& magnet_uri) {
    SILK_TRACE << "Magnet URI from file: " << magnet_uri;
    auto add_magnet = lt::parse_magnet_uri(magnet_uri);
    if (exists_resume_file(add_magnet.info_hashes)) {
        SILK_TRACE << "Resume file found: " << resume_file_path(add_magnet.info_hashes);
        return;
    }
    add_magnet.save_path = settings_.repository_path.string();
    session_.async_add_torrent(std::move(add_magnet));
}

fs::path BitTorrentClient::resume_file_path(const lt::info_hash_t& info_hashes) const {
    const lt::sha1_hash torrent_best_hash{info_hashes.get_best()};
    auto resume_file_name = to_hex({reinterpret_cast<const uint8_t*>(torrent_best_hash.data()), lt::sha1_hash::size()});
    resume_file_name.append(kResumeFileExt);
    SILK_TRACE << "Resume file name: " << resume_file_name;
    return resume_dir_ / resume_file_name;
}

bool BitTorrentClient::exists_resume_file(const lt::info_hash_t& info_hashes) const {
    return std::filesystem::exists(resume_file_path(info_hashes));
}

void BitTorrentClient::execution_loop() {
    SILK_TRACE << "BitTorrentClient::execution_loop start";

    stats_metrics_ = lt::session_stats_metrics();

    int poll_count{0};
    bool stopped{false};
    while (!stopped) {
        poll_count = poll_count % settings_.number_of_polls_between_stats;

        request_torrent_updates(!poll_count);
        process_alerts();

        std::unique_lock stop_lock{stop_mutex_};
        stopped = stop_condition_.wait_for(stop_lock, settings_.wait_between_alert_polls, [this] { return is_stopping(); });
    }
    SILK_TRACE << "Execution loop completed [stop_condition=" << is_stopping() << "]";

    request_save_resume_data(lt::torrent_handle::save_info_dict);
    while (outstanding_resume_requests_ > 0) {
        const auto* alert = session_.wait_for_alert(settings_.wait_between_alert_polls);
        if (alert == nullptr) continue;
        process_alerts();
    }
    SILK_TRACE << "Resume data saved after execution loop completion";

    const auto session_params_data{lt::write_session_params_buf(session_.session_state())};
    BitTorrentClient::save_file(session_file_, session_params_data);
    SILK_TRACE << "Session saved after execution loop completion";

    SILK_TRACE << "BitTorrentClient::execution_loop end";
}

void BitTorrentClient::recheck_all_finished_torrents() const {
    int rechecked_count{0};
    for (const auto& torrent_handle : session_.get_torrents()) {  // NOLINT(readability-use-anyofallof)
        if (torrent_handle.status().is_finished) {
            torrent_handle.force_recheck();
            ++rechecked_count;
        }
    }
    SILK_INFO << "Recheck finished torrents count=" << rechecked_count;
}

void BitTorrentClient::request_torrent_updates(bool stats_included) {
    SILK_TRACE << "BitTorrentClient::request_torrent_updates start";
    // Ask the session to post update alerts for our torrents
    session_.post_torrent_updates();
    if (stats_included) {
        session_.post_session_stats();
    }

    // Save resume data every once in a while
    if (std::chrono::steady_clock::now() - last_save_resume_ >= settings_.resume_data_save_interval) {
        request_save_resume_data(lt::torrent_handle::save_info_dict);
        last_save_resume_ = std::chrono::steady_clock::now();
    }
    SILK_TRACE << "BitTorrentClient::request_torrent_updates end";
}

void BitTorrentClient::request_save_resume_data(lt::resume_data_flags_t flags) {
    SILK_TRACE << "BitTorrentClient::request_save_resume_data start";
    const auto if_need_save_resume = [](auto& ts) { return ts.need_save_resume; };
    for (const auto& torrent_status : session_.get_torrent_status(if_need_save_resume)) {
        torrent_status.handle.save_resume_data(flags);
        ++outstanding_resume_requests_;
        SILK_TRACE << "Save resume data requested for: " << torrent_status.name;
    }
    SILK_TRACE << "BitTorrentClient::request_save_resume_data end";
}

void BitTorrentClient::process_alerts() {
    std::vector<lt::alert*> session_alerts;
    session_.pop_alerts(&session_alerts);
    SILK_TRACE << "Session raised #alerts: " << session_alerts.size();

    for (const auto* alert : session_alerts) {
        handle_alert(alert);
    }
}

bool BitTorrentClient::handle_alert(const lt::alert* alert) {
    bool handled{false};
    if (const auto ata = lt::alert_cast<lt::add_torrent_alert>(alert)) {
        if (ata->error) {
            SILK_ERROR << "Failed to add torrent: " << (ata->params.ti ? ata->params.ti->name() : ata->params.name)
                       << " message: " << ata->error.message();
        } else {
            SILK_TRACE << "Torrent: " << ata->torrent_name() << " added";
            ata->handle.save_resume_data(lt::torrent_handle::save_info_dict | lt::torrent_handle::only_if_modified);
            ++outstanding_resume_requests_;

            // Notify that torrent file has been added to registered subscribers
            added_subscription(settings_.repository_path / ata->torrent_name());
        }
        handled = true;
    }

    // When we receive the finished alert, we request to save resume data for the torrent
    if (const auto* tfa = lt::alert_cast<lt::torrent_finished_alert>(alert)) {
        const auto& status = tfa->handle.status();
        std::tm completed_calendar_time{};
#ifdef _MSC_VER
        SILKWORM_ASSERT(gmtime_s(&completed_calendar_time, &status.completed_time) == 0);
#else
        SILKWORM_ASSERT(gmtime_r(&status.completed_time, &completed_calendar_time) != nullptr);
#endif
        SILK_TRACE << "Torrent: " << tfa->torrent_name() << " finished download_rate: " << (status.download_rate / 1000) << " kB/s"
                   << " download_payload_rate: " << (status.download_payload_rate / 1000) << " kB/s"
                   << " in " << (status.completed_time - status.added_time) << " sec at "
                   << std::put_time(&completed_calendar_time, "%c %Z");

        tfa->handle.save_resume_data(lt::torrent_handle::save_info_dict | lt::torrent_handle::flush_disk_cache);
        ++outstanding_resume_requests_;

        // Notify that torrent file has been downloaded to registered subscribers
        completed_subscription(settings_.repository_path / tfa->torrent_name());

        handled = true;
    }

    if (const auto* mra = alert_cast<lt::metadata_received_alert>(alert)) {
        SILK_TRACE << "Torrent: " << mra->torrent_name() << " metadata received";
        mra->handle.save_resume_data(lt::torrent_handle::save_info_dict);
        ++outstanding_resume_requests_;
        handled = true;
    }

    // When resume data is ready, we save it to disk
    if (const auto* rda = lt::alert_cast<lt::save_resume_data_alert>(alert)) {
        const auto resume_params_data{lt::write_resume_data_buf(rda->params)};
        BitTorrentClient::save_file(resume_file_path(rda->params.info_hashes), resume_params_data);
        SILK_TRACE << "Torrent: " << rda->torrent_name() << " resume data saved";
        --outstanding_resume_requests_;
        handled = true;
    }

    if (const auto fa = lt::alert_cast<lt::save_resume_data_failed_alert>(alert)) {
        SILK_TRACE << "Torrent: " << fa->torrent_name() << " save resume data failed ["
                   << (fa->error == lt::errors::resume_data_not_modified ? "not modified" : ("error=" + fa->error.to_string()))
                   << "]";
        --outstanding_resume_requests_;
        handled = true;
    }

    // When we receive a state update, report stats
    if (const auto sta = lt::alert_cast<lt::state_update_alert>(alert)) {
        if (!sta->status.empty()) {
            for (const auto& ts : sta->status) {
                SILK_TRACE << "Torrent: " << ts.name << " id: " << ts.handle.id() << " state: " << magic_enum::enum_name(ts.state) << " "
                           << (ts.download_payload_rate / 1'000'000) << " MB/s " << (ts.total_done / 1'000'000) << " MB ("
                           << (ts.progress_ppm / 10'000) << "%) downloaded (" << ts.num_peers << " peers)";
            }
        } else {
            SILK_TRACE << "Empty state update alert:" << sta->message();
        }
        handled = true;
    }

    // When we receive any session stats alert, report stats
    if (const auto ssa = lt::alert_cast<lt::session_stats_alert>(alert)) {
        stats_subscription(ssa->counters());
        handled = true;
    }

    // When we receive any error alert, put it out as warning if required (there can be many)
    if (settings_.warn_on_error_alerts) {
        if (const auto tea = lt::alert_cast<lt::tracker_error_alert>(alert)) {
            SILK_WARN << "tracker_error_alert: " << alert->message() << " [error=" << tea->error_message() << " reason=" << tea->failure_reason() << "]";
            handled = true;
        }
        if (const auto sfa = lt::alert_cast<lt::scrape_failed_alert>(alert)) {
            SILK_WARN << "scrape_failed_alert: " << alert->message() << " [error=" << sfa->error_message() << " what=" << sfa->what() << "]";
            handled = true;
        }
        if (const auto sea = lt::alert_cast<lt::session_error_alert>(alert)) {
            SILK_WARN << "session_error_alert: " << alert->message() << " [error_code=" << sea->error << " what=" << sea->what() << "]";
            handled = true;
        }
        if (const auto pea = lt::alert_cast<lt::peer_error_alert>(alert)) {
            SILK_WARN << "peer_error_alert: " << alert->message() << " [error_code=" << pea->error << " what=" << pea->what() << "]";
            handled = true;
        }
        if (const auto tea = lt::alert_cast<lt::torrent_error_alert>(alert)) {
            SILK_WARN << "torrent_error_alert: " << alert->message() << " [error_code=" << tea->error << " what=" << tea->what() << "]";
            handled = true;
        }
    }

    // When we receive any performance alert, put it out as warning
    if (const auto pa = lt::alert_cast<lt::performance_alert>(alert)) {
        SILK_WARN << alert->message() << " [warning_code=" << pa->warning_code << "]";
        handled = true;
    }

    // Finally, if an alert has not been unhandled yet, just log it for debug purposes
    if (!handled) {
        SILK_TRACE << alert->message();
    }

    return handled;
}

}  // namespace silkworm::snapshots::bittorrent
