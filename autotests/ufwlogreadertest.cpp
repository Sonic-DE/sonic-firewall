// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#include "ufwlogreader.h"

#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QTest>

namespace
{
const QString ufw1 = QStringLiteral("Sep 16 12:39:56 host kernel: [UFW BLOCK] IN=eth0 SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP SPT=1 DPT=2");
const QString ufw2 = QStringLiteral("Sep 16 12:40:00 host kernel: [UFW BLOCK] IN=eth0 SRC=3.3.3.3 DST=2.2.2.2 PROTO=UDP SPT=3 DPT=4");
const QString ufw3 = QStringLiteral("Sep 16 12:41:00 host kernel: [UFW ALLOW] IN=eth0 SRC=5.5.5.5 DST=2.2.2.2 PROTO=TCP SPT=5 DPT=6");
const QString other = QStringLiteral("Sep 16 12:39:57 host sshd[42]: Accepted publickey for root");
const QString kernel = QStringLiteral("Sep 16 12:39:58 host kernel: usb 1-1: new device");

bool write(const QString &path, const QStringList &lines)
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        return false;
    }
    for (const QString &line : lines) {
        file.write(line.toUtf8() + '\n');
    }
    return true;
}
}

class UfwLogReaderTest : public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void filterUfwLines()
    {
        const QStringList lines{other, ufw1, kernel, ufw2, ufw3};
        QCOMPARE(UfwLogReader::filterUfwLines(lines, 100), (QStringList{ufw1, ufw2, ufw3}));
        QCOMPARE(UfwLogReader::filterUfwLines(lines, 2), (QStringList{ufw2, ufw3}));
    }

    void newLines()
    {
        const QStringList lines{ufw1, ufw2, ufw3};
        QCOMPARE(UfwLogReader::newLines(lines, QString()), lines);
        QCOMPARE(UfwLogReader::newLines(lines, QStringLiteral("absent")), lines);
        QCOMPARE(UfwLogReader::newLines(lines, ufw1), (QStringList{ufw2, ufw3}));
        QCOMPARE(UfwLogReader::newLines(QStringList{ufw1, ufw2, ufw1, ufw3}, ufw1), QStringList{ufw3});
        QVERIFY(UfwLogReader::newLines(lines, ufw3).isEmpty());
    }

    void readSyslogTail()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString missing = dir.filePath(QStringLiteral("missing.log"));
        const QString quiet = dir.filePath(QStringLiteral("quiet.log"));
        const QString busy = dir.filePath(QStringLiteral("busy.log"));
        QVERIFY(write(quiet, {other, kernel}));
        QVERIFY(write(busy, {other, ufw1, kernel, ufw2, other, ufw3}));

        // Missing and quiet files are skipped; only [UFW lines come back, without newlines, in order.
        const QStringList all = UfwLogReader::readSyslogTail({missing, quiet, busy}, 1024 * 1024, 100);
        QCOMPARE(all, (QStringList{ufw1, ufw2, ufw3}));
        for (const QString &line : all) {
            QVERIFY(!line.endsWith(u'\n'));
            QVERIFY(!line.endsWith(u'\r'));
        }
        QCOMPARE(UfwLogReader::readSyslogTail({busy}, 1024 * 1024, 2), (QStringList{ufw2, ufw3}));
        QVERIFY(UfwLogReader::readSyslogTail({missing, quiet}, 1024 * 1024, 100).isEmpty());

        // A tail cut in the middle of a line drops that partial line.
        const qint64 lastTwo = (ufw3 + u'\n').toUtf8().size() + (other + u'\n').toUtf8().size();
        QCOMPARE(UfwLogReader::readSyslogTail({busy}, lastTwo + 10, 100), QStringList{ufw3});
    }

    void rotatedFile()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString kern = dir.filePath(QStringLiteral("kern.log"));
        QVERIFY(write(kern, {kernel}));
        QVERIFY(write(kern + QStringLiteral(".1"), {ufw1, ufw2}));
        QCOMPARE(UfwLogReader::readSyslogTail({kern, kern + QStringLiteral(".1")}, 1024 * 1024, 100), (QStringList{ufw1, ufw2}));
    }

    void defaultSyslogPaths()
    {
        const QStringList paths = UfwLogReader::defaultSyslogPaths();
        QVERIFY(!paths.isEmpty());
        QCOMPARE(paths.size() % 2, 0);
        for (qsizetype i = 0; i < paths.size(); i += 2) {
            QCOMPARE(paths.at(i + 1), paths.at(i) + QStringLiteral(".1"));
        }
        for (const QString &path : paths) {
            QVERIFY(!path.endsWith(QLatin1String(".gz")));
        }
    }

    void journalAvailable()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        QVERIFY(!UfwLogReader::journalAvailable(dir.path()));

        // A regular file isn't a socket.
        QVERIFY(QDir().mkpath(dir.filePath(QStringLiteral("run/systemd/journal"))));
        QVERIFY(write(dir.filePath(QStringLiteral("run/systemd/journal/socket")), {}));
        QVERIFY(!UfwLogReader::journalAvailable(dir.path()));
    }
};

QTEST_GUILESS_MAIN(UfwLogReaderTest)

#include "ufwlogreadertest.moc"
