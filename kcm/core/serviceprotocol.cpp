// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#include "serviceprotocol.h"
#include "initsystem.h"

#include <QDataStream>
#include <QIODevice>

#include <KLocalizedString>

namespace ServiceProtocol
{
namespace
{
// KAuth::ActionReply::AuthorizationDeniedError, which main.qml ignores.
constexpr qint32 authorizationDenied = 4;
}

QString socketPath()
{
    return QStringLiteral("/run/sonic-firewall/service.sock");
}

std::optional<Reply> authorizationReply(bool authorized, bool challenge)
{
    if (authorized) {
        return std::nullopt;
    }
    if (challenge) {
        return Reply{InitSystem::NoAuthenticationAgent, i18n("No authentication agent is running, so you couldn't be asked for your password")};
    }
    return Reply{authorizationDenied, i18n("Not authorized to manage the firewall service")};
}

QByteArray encode(const Request &request)
{
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream.setVersion(QDataStream::Qt_6_0);
    stream << request.service << request.enable << request.serviceOnly;
    return payload;
}

QByteArray encode(const Reply &reply)
{
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream.setVersion(QDataStream::Qt_6_0);
    stream << reply.code << reply.message;
    return payload;
}

std::optional<Request> decodeRequest(const QByteArray &payload)
{
    QDataStream stream(payload);
    stream.setVersion(QDataStream::Qt_6_0);
    Request request;
    stream >> request.service >> request.enable >> request.serviceOnly;
    if (stream.status() != QDataStream::Ok || !stream.atEnd()) {
        return std::nullopt;
    }
    return request;
}

std::optional<Reply> decodeReply(const QByteArray &payload)
{
    QDataStream stream(payload);
    stream.setVersion(QDataStream::Qt_6_0);
    Reply reply;
    stream >> reply.code >> reply.message;
    if (stream.status() != QDataStream::Ok || !stream.atEnd()) {
        return std::nullopt;
    }
    return reply;
}
}
