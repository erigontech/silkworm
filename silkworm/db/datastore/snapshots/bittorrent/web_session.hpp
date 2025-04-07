// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <map>
#include <memory>
#include <optional>
#include <string_view>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/beast/http.hpp>
#include <boost/url/url.hpp>

namespace silkworm::snapshots::bittorrent {

class WebSession {
  public:
    //! \brief Constructor optionally accepting a server certificate to append to root certificates
    //! \remarks the custom server certificate is used only in tests
    explicit WebSession(std::optional<std::string> server_certificate = {});
    virtual ~WebSession() = default;

    using HeaderFields = std::map<std::string_view, std::string_view>;
    using StringResponse = boost::beast::http::response<boost::beast::http::string_body>;

    //! \brief Asynch send a HTTPS GET request for \p target file to \p web_url and receive the response
    //! \param web_url the URL address of the web server
    //! \param target_file the relative path of the requested file
    //! \param custom_fields the custom fields to add to the header of HTTPS requests, if any
    virtual Task<StringResponse> https_get(
        const boost::urls::url& web_url,
        std::string_view target_file,
        const HeaderFields& custom_fields) const;

  protected:
    using EmptyRequest = boost::beast::http::request<boost::beast::http::empty_body>;
    static void include_custom_headers(EmptyRequest& request, const HeaderFields& custom_fields);

    //! The HTTP protocol version to use
    static constexpr int kHttpVersion{11};

    std::optional<std::string> server_certificate_;
};

}  // namespace silkworm::snapshots::bittorrent
