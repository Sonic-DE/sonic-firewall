// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#pragma once

#include <QByteArray>
#include <QString>

#include <optional>

// The wire format between the KCM and sonic-firewall-service: one Manage frame, one Result frame back.
namespace ServiceProtocol
{
constexpr quint16 version = 1;
constexpr qint64 maxPayload = 4096;
enum Message : quint32 { Manage = 1, Result = 2 };
struct Request {
    QString service;
    bool enable = false;
    bool serviceOnly = false;
};
struct Reply {
    qint32 code = 0; // 0 ok, InitSystem::Status, or 4 = authorization denied
    QString message;
};
// AuthorizationUnavailable (-105) means polkit was never asked, so no prompt was shown; the KCM then uses KAuth.
QString socketPath(); // "/run/sonic-firewall/service.sock"
// Maps polkit's (is authorized, is challenge) to what the daemon does: nullopt = authorised, go ahead;
// otherwise the Reply to send. Not authorised + challenge -> InitSystem::NoAuthenticationAgent (shown by the
// KCM); not authorised, no challenge -> 4 (denied or cancelled, which the KCM ignores).
std::optional<Reply> authorizationReply(bool authorized, bool challenge);
QByteArray encode(const Request &request);
QByteArray encode(const Reply &reply);
std::optional<Request> decodeRequest(const QByteArray &payload);
std::optional<Reply> decodeReply(const QByteArray &payload);
}
