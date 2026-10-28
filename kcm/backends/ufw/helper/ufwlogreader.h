// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#pragma once

#include <QString>
#include <QStringList>

// Where the ufw helper finds "[UFW " kernel log lines: the journal, syslog files, or the kernel ring buffer.
namespace UfwLogReader
{
// Lines after the last line equal to lastLine; all lines if lastLine is empty or absent.
QStringList newLines(const QStringList &lines, const QString &lastLine);
// Each of "/var/log/ufw.log", "/var/log/kern.log", "/var/log/kernel.log", "/var/log/messages",
// "/var/log/syslog", "/var/log/everything.log", immediately followed by its uncompressed rotation "<path>.1".
QStringList defaultSyslogPaths();
// Last maxLines lines containing "[UFW " from the first readable file in paths that has any; reads at most
// maxBytes from the end of each file.
QStringList readSyslogTail(const QStringList &paths, qint64 maxBytes, int maxLines);
// Sonic::InitInfo::hasJournald({.fsRoot = root}) and journalctl found in the system binary directories or PATH.
bool journalAvailable(const QString &root = QString());
// The last maxLines lines containing "[UFW ", in order.
QStringList filterUfwLines(const QStringList &lines, int maxLines);
// `dmesg` output (root only) passed through filterUfwLines; {} if dmesg is missing or fails.
QStringList readDmesg(int maxLines);
// The program path for journalctl or dmesg, searched like the init tools; empty if missing.
QString findTool(const QString &name);
}
