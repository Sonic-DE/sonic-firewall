// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#include "ufwlogreader.h"

#include <QFile>
#include <QProcess>
#include <QStandardPaths>

#include <Sonic/InitInfo/InitInfo>

namespace UfwLogReader
{
namespace
{
const QString ufwMarker = QStringLiteral("[UFW ");
}

QStringList newLines(const QStringList &lines, const QString &lastLine)
{
    QStringList result;
    for (const QString &line : lines) {
        if (!lastLine.isEmpty() && line == lastLine) {
            result.clear();
            continue;
        }
        result.append(line);
    }
    return result;
}

QStringList defaultSyslogPaths()
{
    QStringList paths;
    for (const QString &path : {QStringLiteral("/var/log/ufw.log"),
                                QStringLiteral("/var/log/kern.log"),
                                QStringLiteral("/var/log/kernel.log"),
                                QStringLiteral("/var/log/messages"),
                                QStringLiteral("/var/log/syslog"),
                                QStringLiteral("/var/log/everything.log")}) {
        paths << path << path + QStringLiteral(".1");
    }
    return paths;
}

QStringList filterUfwLines(const QStringList &lines, int maxLines)
{
    QStringList result;
    for (const QString &line : lines) {
        if (line.contains(ufwMarker)) {
            result.append(line);
        }
    }
    if (result.size() > maxLines) {
        result = result.mid(result.size() - maxLines);
    }
    return result;
}

QStringList readSyslogTail(const QStringList &paths, qint64 maxBytes, int maxLines)
{
    for (const QString &path : paths) {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) {
            continue;
        }
        if (file.size() > maxBytes) {
            file.seek(file.size() - maxBytes);
            file.readLine(); // partial
        }
        QStringList lines;
        while (!file.atEnd()) {
            QString line = QString::fromUtf8(file.readLine());
            while (line.endsWith(u'\n') || line.endsWith(u'\r')) {
                line.chop(1);
            }
            lines.append(line);
        }
        const QStringList ufwLines = filterUfwLines(lines, maxLines);
        if (!ufwLines.isEmpty()) {
            return ufwLines;
        }
    }
    return {};
}

QString findTool(const QString &name)
{
    // The same directories as InitSystem::systemBinaryPaths(), duplicated so the ufw helper's log code
    // doesn't need kcm_firewall_initsystem.
    QString path = QStandardPaths::findExecutable(name,
                                                  {QStringLiteral("/sbin"),
                                                   QStringLiteral("/usr/sbin"),
                                                   QStringLiteral("/bin"),
                                                   QStringLiteral("/usr/bin"),
                                                   QStringLiteral("/usr/local/sbin"),
                                                   QStringLiteral("/usr/local/bin")});
    if (path.isEmpty()) {
        path = QStandardPaths::findExecutable(name);
    }
    return path;
}

bool journalAvailable(const QString &root)
{
    Sonic::InitInfo::Environment environment;
    environment.fsRoot = root;
    return Sonic::InitInfo::hasJournald(environment) && !findTool(QStringLiteral("journalctl")).isEmpty();
}

QStringList readDmesg(int maxLines)
{
    const QString dmesg = findTool(QStringLiteral("dmesg"));
    if (dmesg.isEmpty()) {
        return {};
    }
    QProcess process;
    process.start(dmesg, {});
    if (!process.waitForStarted(10000)) {
        return {};
    }
    if (!process.waitForFinished(10000)) {
        process.kill();
        process.waitForFinished(1000);
        return {};
    }
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        return {};
    }
    return filterUfwLines(QString::fromUtf8(process.readAllStandardOutput()).split(u'\n'), maxLines);
}
}
