// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

#include "ufwlogmodel.h"

#include <QRegularExpression>

#include <Sonic/Logging/Log>

#include <algorithm>
#include <iterator>
#include <map>

UfwLogModel::UfwLogModel(QObject *parent)
    : LogListModel(parent)
{
}

// Parses one kernel log line, for example
//   Dec 06 17:42:45 tomatoland kernel: [UFW BLOCK] IN=wlan0 OUT= MAC= SRC=192.168.50.181 DST=224.0.0.252 ... PROTO=UDP SPT=5355 DPT=5355
// from the journal or a syslog file (space-padded days and RFC 3339 stamps included), or from dmesg (no date).
// Returns {} for anything that isn't a ufw entry.
std::map<QString, QString> parseString(const QString &line)
{
    const QStringList tokens = line.split(QLatin1Char(' '), Qt::SkipEmptyParts);
    const auto marker = std::find_if(tokens.cbegin(), tokens.cend(), [](const QString &token) {
        return token.startsWith(QLatin1String("[UFW"));
    });
    if (marker == tokens.cend()) {
        return {};
    }
    const qsizetype markerIndex = std::distance(tokens.cbegin(), marker);

    std::map<QString, QString> results;
    static const QRegularExpression rfc3339(QStringLiteral("^(\\d{4}-\\d{2}-\\d{2})T(\\d{2}:\\d{2}:\\d{2})"));
    const QRegularExpressionMatch match = rfc3339.match(tokens.first());
    if (match.hasMatch()) {
        results[QStringLiteral("date")] = match.captured(1);
        results[QStringLiteral("time")] = match.captured(2);
    } else if (markerIndex >= 3) {
        results[QStringLiteral("date")] = tokens[0] + QLatin1Char(' ') + tokens[1];
        results[QStringLiteral("time")] = tokens[2];
    }

    static const QStringList keys{QStringLiteral("IN"), QStringLiteral("SRC"), QStringLiteral("DST"), QStringLiteral("PROTO"), QStringLiteral("SPT"), QStringLiteral("DPT")};
    for (qsizetype i = markerIndex + 1; i < tokens.size(); ++i) {
        const QString &token = tokens[i];
        for (const QString &key : keys) {
            // The kernel writes each key once, in this order; the first occurrence wins.
            if (token.startsWith(key + u'=') && results.find(key) == results.end()) {
                results[key] = token.mid(key.size() + 1);
            }
        }
    }

    return results;
}

void UfwLogModel::addRawLogs(const QStringList &rawLogsList)
{
    QList<LogData> newLogs;
    newLogs.reserve(rawLogsList.count());
    for (const QString &log : rawLogsList) {
        auto map = parseString(log);
        // Lines that aren't ufw entries would otherwise become empty rows.
        if (map.empty()) {
            continue;
        }

        LogData logDetails{.sourceAddress = map["SRC"],
                           .sourcePort = map["SPT"],
                           .destinationAddress = map["DST"],
                           .destinationPort = map["DPT"],
                           .protocol = map["PROTO"],
                           .interface = map["IN"],
                           .action = "",
                           .time = map["time"],
                           .date = map["date"]};
        newLogs.append(logDetails);
    }
    sonicDebug() << "Number of logs" << newLogs.count();
    appendLogData(newLogs);
}

#include "moc_ufwlogmodel.cpp"
