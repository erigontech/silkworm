// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/url/url.hpp>
// Disable warnings raised during compilation of libtorrent
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wc++11-compat"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <libtorrent/torrent_info.hpp>
#pragma GCC diagnostic pop

#include <silkworm/infra/concurrency/task.hpp>

#include "web_session.hpp"

namespace silkworm::snapshots::bittorrent {

using TorrentFileList = std::vector<std::string>;
using TorrentsByProvider = std::map<boost::urls::url, TorrentFileList>;
using TorrentInfo = lt::torrent_info;
using TorrentInfoPtr = std::shared_ptr<TorrentInfo>;
inline auto torrent_info_compare = [](const TorrentInfoPtr& lhs, const TorrentInfoPtr& rhs) {
    return lhs->name() < rhs->name();
};
using TorrentInfoPtrList = std::set<TorrentInfoPtr, decltype(torrent_info_compare)>;
using Whitelist = std::vector<std::pair<std::string_view, std::string_view>>;

class WebSeedClient {
  public:
    WebSeedClient(
        std::vector<std::string> url_seeds,
        Whitelist whitelist);
    WebSeedClient(
        std::unique_ptr<WebSession> web_session,
        std::vector<std::string> url_seeds,
        Whitelist whitelist);

    Task<TorrentInfoPtrList> discover_torrents(bool fail_fast = false);

  protected:
    WebSession& web_session() { return *web_session_; }
    Task<void> build_list_of_torrents(bool fail_fast);
    Task<void> build_list_of_torrents(std::string_view provider_url);
    Task<TorrentInfoPtrList> download_and_filter_all_torrents();
    Task<void> download_from_provider(const boost::urls::url& provider_url,
                                      const auto& torrent_files,
                                      TorrentInfoPtrList& torrent_infos);
    TorrentInfoPtr validate_torrent_file(const boost::urls::url& provider_url,
                                         std::string_view torrent_file_name,
                                         std::string_view torrent_content);
    bool is_whitelisted(std::string_view file_name, std::string_view torrent_hash);

    std::vector<std::string> url_seeds_;
    Whitelist whitelist_;
    std::unique_ptr<WebSession> web_session_;
    TorrentsByProvider torrents_by_provider_;
    bool throw_not_whitelisted_{false};
};

}  // namespace silkworm::snapshots::bittorrent
