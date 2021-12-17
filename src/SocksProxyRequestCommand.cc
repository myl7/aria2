/* <!-- copyright */
/*
 * aria2 - The high speed download utility
 *
 * Copyright (C) 2006 Tatsuhiro Tsujikawa
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */
/* copyright --> */
#include "SocksProxyRequestCommand.h"
#include "HttpRequestCommand.h"
#include "Request.h"
#include "HttpConnection.h"
#include "HttpRequest.h"
#include "Segment.h"
#include "SocketCore.h"
#include "SocketRecvBuffer.h"
#include "Option.h"
#include "DownloadEngine.h"
#include "a2functional.h"
#include "uri.h"

namespace aria2 {

SocksProxyRequestCommand::SocksProxyRequestCommand(
    cuid_t cuid, const std::shared_ptr<Request>& req,
    const std::shared_ptr<FileEntry>& fileEntry, RequestGroup* requestGroup,
    DownloadEngine* e, const std::shared_ptr<Request>& proxyRequest,
    const std::shared_ptr<SocketCore>& s)
    : AbstractProxyRequestCommand(cuid, req, fileEntry, requestGroup, e,
                                  proxyRequest, s)
{
}

SocksProxyRequestCommand::~SocksProxyRequestCommand() = default;

std::unique_ptr<Command> SocksProxyRequestCommand::getNextCommand()
{
  return make_unique<HttpRequestCommand>(
      getCuid(), getRequest(), getFileEntry(), getRequestGroup(),
      getHttpConnection(), getDownloadEngine(), getSocket());
}

bool SocksProxyRequestCommand::executeInternal()
{
  auto httpConnection = getHttpConnection();
  if (httpConnection->sendBufferIsEmpty()) {
    // Prepare SOCKS proxy options
    const std::string& proxyUri = getOption()->get(PREF_SOCKS_PROXY);
    uri::UriStruct us;
    uri::parse(us, proxyUri);
    const std::string& host = us.host;
    uint16_t port = us.port;
    const std::string& user = getOption()->get(PREF_SOCKS_PROXY_USER);
    const std::string& passwd = getOption()->get(PREF_SOCKS_PROXY_PASSWD);

    auto proxySocket =
        std::make_shared<SocksProxySocket>(getSocket()->getAddressFamily());
    proxySocket->establish(host, port);

    // Authentication negotiation
    bool noAuth = user.empty() || passwd.empty();
    if (noAuth) {
      int authMethod =
          proxySocket->negotiateAuth(std::vector<uint8_t>{SOCKS_AUTH_NO_AUTH});
      if (authMethod < 0) {
        return false;
      }
    }
    else {
      int authMethod = proxySocket->negotiateAuth(
          std::vector<uint8_t>{SOCKS_AUTH_NO_AUTH, SOCKS_AUTH_USERPASS});
      if (authMethod < 0) {
        return false;
      }

      // Username/Password authentication
      if (authMethod == SOCKS_AUTH_USERPASS) {
        int status = proxySocket->authByUserpass(user, passwd);
        if (status != 0) {
          return false;
        }
      }
    }

    // Start TCP SOCKS Connect proxy
    std::string bndAddr;
    uint16_t bndPort;
    ssize_t i =
        proxySocket->startTcpConnect("", 0, std::make_pair(&bndAddr, &bndPort));
    if (i < 0) {
      return false;
    }

    httpConnection->setProxySocket(proxySocket);
    // TODO: Overwrite TCP socket destination
  }
  else {
    httpConnection->sendPendingData();
  }
  if (httpConnection->sendBufferIsEmpty()) {
    getDownloadEngine()->addCommand(getNextCommand());
    return true;
  }
  else {
    setWriteCheckSocket(getSocket());
    addCommandSelf();
    return false;
  }
}

} // namespace aria2
