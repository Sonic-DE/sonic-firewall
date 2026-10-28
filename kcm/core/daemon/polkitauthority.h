// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#pragma once

#include <QDBusArgument>
#include <QMap>
#include <QMetaType>
#include <QString>
#include <QVariantMap>

#include <functional>

namespace Sonic::Ipc
{
class Connection;
}

// polkit's subject, (sa{sv}).
struct PolkitSubject {
    QString kind;
    QVariantMap details;
};
Q_DECLARE_METATYPE(PolkitSubject)

// polkit's CheckAuthorization result, (bba{ss}).
struct PolkitResult {
    bool authorized = false;
    bool challenge = false;
    QMap<QString, QString> details;
};
Q_DECLARE_METATYPE(PolkitResult)

QDBusArgument &operator<<(QDBusArgument &argument, const PolkitSubject &subject);
const QDBusArgument &operator>>(const QDBusArgument &argument, PolkitSubject &subject);
QDBusArgument &operator<<(QDBusArgument &argument, const PolkitResult &result);
const QDBusArgument &operator>>(const QDBusArgument &argument, PolkitResult &result);

struct PolkitDecision {
    bool reached = false; // false: polkit was never asked, so no prompt can have been shown
    bool authorized = false;
    bool challenge = false;
    QString error;
};

namespace PolkitAuthority
{
// Asks polkit whether the connection's peer may perform actionId, allowing a password prompt. done is called
// at most once, on the main thread, and never after the connection is deleted.
void check(Sonic::Ipc::Connection *connection, const QString &actionId, std::function<void(const PolkitDecision &)> done);
}
