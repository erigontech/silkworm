/*
   Copyright 2024 The Silkworm Authors

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

#include "web_seed_client.hpp"

#include <chrono>
#include <map>
#include <string_view>

#include <absl/strings/ascii.h>
#include <absl/strings/str_split.h>
#include <boost/system/system_error.hpp>
#include <boost/url/parse.hpp>
// Disable warnings raised during compilation of libtorrent
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wc++11-compat"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <libtorrent/hex.hpp>
#pragma GCC diagnostic pop

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/parallel_group_utils.hpp>
#include <silkworm/infra/concurrency/timeout.hpp>

namespace silkworm::snapshots::bittorrent {

using namespace std::literals;

namespace system = boost::system;
namespace urls = boost::urls;

//! HTTP target for Manifest file containing the list of available snapshot files
static constexpr std::string_view kManifestTarget{"/manifest.txt"sv};

//! The BitTorrent file extension for torrent files
static constexpr std::string_view kTorrentExtension{".torrent"sv};

//! Timeout for parallel async download of manifest files in msec
static const std::chrono::milliseconds kParallelManifestDownloadTimeout{60'000};

//! Timeout for parallel async download of torrent files in msec
static const std::chrono::milliseconds kParallelTorrentDownloadTimeout{120'000};

//! Custom HTTP header fields to include in any request to web servers hosted by Cloudflare
static const std::map<std::string_view, std::string_view> kCloudflareHeaders{
    {"lsjdjwcush6jbnjj3jnjscoscisoc5s", "I%OSJDNFKE783DDHHJD873EFSIVNI7384R78SSJBJBCCJBC32JABBJCBJK45"},
};

WebSeedClient::WebSeedClient(std::vector<std::string> url_seeds, const PreverifiedList& preverified)
    : WebSeedClient(std::make_unique<WebSession>(), std::move(url_seeds), preverified) {}

WebSeedClient::WebSeedClient(std::unique_ptr<WebSession> web_session,
                             std::vector<std::string> url_seeds,
                             const PreverifiedList& preverified)
    : url_seeds_{std::move(url_seeds)},
      preverified_{preverified},
      web_session_{std::move(web_session)} {}

Task<TorrentInfoPtrList> WebSeedClient::discover_torrents(bool fail_fast) {
    torrents_by_provider_.clear();
    co_await build_list_of_torrents(fail_fast);
    co_return co_await download_and_filter_all_torrents();
}

Task<void> WebSeedClient::build_list_of_torrents(bool fail_fast) {
    using namespace concurrency::awaitable_wait_for_one;

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-capturing-lambda-coroutines)
    auto build_list_of_torrents_factory = [this, fail_fast](size_t index) -> Task<void> {
        const auto& provider_url = url_seeds_[index];
        try {
            co_await build_list_of_torrents(provider_url);
        } catch (const std::exception& e) {
            if (fail_fast) throw;
            SILK_WARN << "Cannot retrieve the torrent list from: " << provider_url << " what: " << e.what();
        }
    };

    // Parallelize async build of the list of torrent files for each provider
    auto group_task = concurrency::generate_parallel_group_task(url_seeds_.size(), build_list_of_torrents_factory);
    co_await (std::move(group_task) || concurrency::timeout(kParallelManifestDownloadTimeout));
}

Task<void> WebSeedClient::build_list_of_torrents(std::string_view provider_url) {
    const auto web_url_result = urls::parse_uri(provider_url);
    if (!web_url_result) {
        throw system::system_error{web_url_result.error(), "invalid provider URL"};
    }

    const auto response = co_await web_session_->https_get(*web_url_result, kManifestTarget, kCloudflareHeaders);
    SILK_TRACE << "Web seed manifest downloaded from: " << provider_url;

    // Parse HTTP response body content as snapshot Manifest containing list of snapshot files
    TorrentFileList torrent_files;
    const auto manifest_file_lines = absl::StrSplit(response.body(), '\n');
    for (const auto manifest_line : manifest_file_lines) {
        const auto snapshot_file_name = absl::StripAsciiWhitespace(manifest_line);
        SILK_TRACE << "WebSeedClient::build_list_of_torrents snapshot_file_name: " << snapshot_file_name;
        if (snapshot_file_name.empty() || !absl::EndsWith(snapshot_file_name, ".torrent")) {
            continue;
        }
        torrent_files.emplace_back(snapshot_file_name);
    }
    torrents_by_provider_.emplace(*web_url_result, std::move(torrent_files));
}

Task<TorrentInfoPtrList> WebSeedClient::download_and_filter_all_torrents() {
    TorrentInfoPtrList torrent_infos;
    for (const auto& [provider_url, torrent_files] : torrents_by_provider_) {
        SILK_TRACE << "WebSeedClient::download_and_filter_all_torrents from provider_url: " << provider_url;
        co_await download_from_provider(provider_url, torrent_files, torrent_infos);
    }
    co_return torrent_infos;
}

Task<void> WebSeedClient::download_from_provider(const urls::url& provider_url,
                                                 const auto& torrent_files,
                                                 TorrentInfoPtrList& torrent_infos) {
    using namespace concurrency::awaitable_wait_for_one;

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-capturing-lambda-coroutines)
    auto download_and_validate_factory = [this, provider_url, &torrent_files, &torrent_infos](size_t index) -> Task<void> {
        const auto& torrent_file = torrent_files[index];
        urls::url torrent_url{provider_url};
        const auto torrent_file_path = torrent_url.set_path(torrent_file).path();
        const auto response = co_await web_session_->https_get(provider_url, torrent_file_path, kCloudflareHeaders);
        SILK_TRACE << "WebSeedClient::download_from_provider received torrent: " << torrent_file;
        TorrentInfoPtr torrent_info = validate_torrent_file(provider_url, torrent_file, response.body());
        SILK_TRACE << "WebSeedClient::download_from_provider validated torrent: " << torrent_file;
        if (torrent_info) {
            torrent_infos.emplace(std::move(torrent_info));
        }
    };

    // Parallelize async download and validate of torrent files for each provider
    auto group_task = concurrency::generate_parallel_group_task(torrent_files.size(), download_and_validate_factory);
    co_await (std::move(group_task) || concurrency::timeout(kParallelTorrentDownloadTimeout));
}

TorrentInfoPtr WebSeedClient::validate_torrent_file(const urls::url& provider_url,
                                                    std::string_view torrent_file_name,
                                                    std::string_view torrent_content) {
    lt::error_code ec;
    auto info{std::make_shared<TorrentInfo>(torrent_content.data(), static_cast<int>(torrent_content.size()), ec)};
    if (ec) {
        throw system::system_error{ec};
    }
    info->add_url_seed(provider_url.c_str());

    const lt::sha1_hash torrent_hash{info->info_hashes().get_best()};

    std::string_view file_name{torrent_file_name};
    file_name.remove_suffix(kTorrentExtension.size());

    if (!is_whitelisted(file_name, lt::aux::to_hex(torrent_hash))) {
        if (WebSeedClient::is_caplin_segment(file_name)) {
            SILK_TRACE << "WebSeedClient::validate_torrent_file skip Caplin torrent: " << file_name;
            return {};
        }
        SILK_WARN << "WebSeedClient::validate_torrent_file torrent NOT whitelisted: " << file_name;
        if (throw_not_whitelisted_) {
            throw std::runtime_error{".torrent file " + std::string{file_name} + " is not whitelisted"};
        }
        return {};
    }

    return info;
}

bool WebSeedClient::is_whitelisted(std::string_view file_name, std::string_view torrent_hash) {
    SILK_TRACE << "WebSeedClient::is_whitelisted file_name: " << file_name << " torrent_hash: " << torrent_hash;
    const auto it = std::find_if(preverified_.cbegin(), preverified_.cend(), [=](auto& preverified_file) {
        const auto [preverified_file_name, preverified_hash] = preverified_file;
        SILK_TRACE << "WebSeedClient::is_whitelisted preverified_file_name: " << preverified_file_name << " preverified_hash: " << preverified_hash;
        return preverified_file_name == file_name && preverified_hash == torrent_hash;
    });
    return it != preverified_.cend();
}

bool WebSeedClient::is_caplin_segment(std::string_view file_name) {
    return file_name.ends_with("beaconblocks.seg") || file_name.ends_with("blobsidecars.seg");
}

}  // namespace silkworm::snapshots::bittorrent
