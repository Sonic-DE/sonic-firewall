// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#pragma once

#include <QByteArray>
#include <QList>
#include <QString>
#include <QStringList>

#include <optional>

#include <Sonic/InitInfo/InitInfo>

namespace InitSystem
{
using Type = Sonic::InitInfo::ServiceManager; // Unknown, Systemd, OpenRC, Runit, S6, Dinit, SysVinit, BsdRc, OpenBsdRc
enum class Action { Start, Stop, Enable, Disable };

struct Operation {
    enum class Kind { Run, Link, Unlink };
    Kind kind = Kind::Run;
    QString program; // Run: bare name or absolute path
    QStringList arguments; // Run
    QString linkTarget; // Link: what the symlink points to
    QString linkPath; // Link/Unlink: the symlink itself
    bool operator==(const Operation &) const = default;
};

// Directories searched for init tools, in this order.
QStringList systemBinaryPaths();

Type detect(); // Sonic::InitInfo::serviceManager(); the only detection entry point
QString typeName(Type type); // Sonic::InitInfo::name(type)
// The command that answers "does this service exist?". Runit, SysVinit and Unknown have no such command and
// return a default-constructed Operation (Kind::Run, empty program); isServiceInstalled checks their files instead.
Operation installedQuery(Type type, const QString &service, const QString &root = QString());
bool isServiceInstalled(Type type, const QString &service, const QString &root = QString());
QString runitSourceDirectory(const QString &service, const QString &root = QString()); // empty if none
QString runitActiveDirectory(const QString &root = QString()); // empty if none
QStringList openrcRunlevels(const QString &service, const QString &root = QString()); // runlevels containing service, sorted
QList<Operation> operations(Type type, Action action, const QString &service, const QString &root = QString());
// Link/Unlink only; returns false and sets *error for Run or on failure.
bool applyFileOperation(const Operation &operation, QString *error);
bool isServiceActive(Type type, const QString &service, const QString &root = QString());
bool isServiceActive(const QString &service); // isServiceActive(detect(), service)

// Root side, shared by the daemon and the KAuth fallback helper.
// The values match the KAuth helper error codes, so both paths report the same numbers.
enum Status : int {
    Ok = 0,
    InvalidArguments = -101,
    OperationFailed = -102,
    UnknownInit = -103,
    ServiceMissing = -104,
    AuthorizationUnavailable = -105, // daemon only: polkit couldn't be asked
    NoAuthenticationAgent = -106, // daemon only: polkit needed a password but no agent could ask for it
};
bool isAllowedService(const QString &service); // exactly "ufw" or "firewalld"
// Field 22 (start time) of a /proc/<pid>/stat line, counted after the last ')' of the command name.
std::optional<quint64> startTimeFromStat(const QByteArray &statLine);
// Runs the steps for one request; returns a Status and sets *message (translated) on failure.
int manage(const QString &service, bool enable, bool serviceOnly, QString *message);
}
