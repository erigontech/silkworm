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
    [[nodiscard]] virtual Task<StringResponse> https_get(const boost::urls::url& web_url,
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
