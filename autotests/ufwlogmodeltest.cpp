// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#include "ufwlogmodel.h"

#include <QTest>

class UfwLogModelTest : public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void parse_data()
    {
        // An empty date or time means the column isn't asserted.
        QTest::addColumn<QString>("line");
        QTest::addColumn<QString>("date");
        QTest::addColumn<QString>("time");
        QTest::addColumn<QString>("interface");
        QTest::addColumn<QString>("source");
        QTest::addColumn<QString>("sourcePort");
        QTest::addColumn<QString>("destination");
        QTest::addColumn<QString>("destinationPort");
        QTest::addColumn<QString>("protocol");

        QTest::newRow("journal") << QStringLiteral(
            "Dec 06 17:42:45 tomatoland kernel: [UFW BLOCK] IN=wlan0 OUT= MAC= SRC=192.168.50.181 DST=224.0.0.252 LEN=56 TOS=0x00 PREC=0x00 TTL=255 "
            "ID=52151 PROTO=UDP SPT=5355 DPT=5355 LEN=36")
                                 << QStringLiteral("Dec 06") << QStringLiteral("17:42:45") << QStringLiteral("wlan0") << QStringLiteral("192.168.50.181")
                                 << QStringLiteral("5355") << QStringLiteral("224.0.0.252") << QStringLiteral("5355") << QStringLiteral("UDP");
        QTest::newRow("space-padded day")
            << QStringLiteral("Sep  6 12:39:56 joseph-work kernel: [UFW BLOCK] IN=enp5s0 OUT= SRC=10.0.0.2 DST=10.0.0.1 PROTO=TCP SPT=40000 DPT=22")
            << QStringLiteral("Sep 6") << QStringLiteral("12:39:56") << QStringLiteral("enp5s0") << QStringLiteral("10.0.0.2") << QStringLiteral("40000")
            << QStringLiteral("10.0.0.1") << QStringLiteral("22") << QStringLiteral("TCP");
        QTest::newRow("kernel timestamp")
            << QStringLiteral("Sep 16 12:39:56 host kernel: [ 1234.567890] [UFW BLOCK] IN=eth0 SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=1 DPT=2") << QString()
            << QString() << QStringLiteral("eth0") << QStringLiteral("1.2.3.4") << QStringLiteral("1") << QStringLiteral("5.6.7.8") << QStringLiteral("2")
            << QStringLiteral("TCP");
        QTest::newRow("key prefix guard")
            << QStringLiteral("Dec 06 17:42:45 host kernel: [UFW BLOCK] INX=bogus IN=eth1 SRC=1.1.1.1 DST=2.2.2.2 PROTO=UDP SPT=3 DPT=4") << QString()
            << QString() << QStringLiteral("eth1") << QStringLiteral("1.1.1.1") << QStringLiteral("3") << QStringLiteral("2.2.2.2") << QStringLiteral("4")
            << QStringLiteral("UDP");
        QTest::newRow("rfc 3339")
            << QStringLiteral("2026-10-27T10:00:00.123456+10:00 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=9.9.9.9 DST=8.8.8.8 PROTO=TCP SPT=5 DPT=6")
            << QStringLiteral("2026-10-27") << QStringLiteral("10:00:00") << QStringLiteral("eth0") << QStringLiteral("9.9.9.9") << QStringLiteral("5")
            << QStringLiteral("8.8.8.8") << QStringLiteral("6") << QStringLiteral("TCP");
    }

    void parse()
    {
        QFETCH(QString, line);
        QFETCH(QString, date);
        QFETCH(QString, time);
        QFETCH(QString, interface);
        QFETCH(QString, source);
        QFETCH(QString, sourcePort);
        QFETCH(QString, destination);
        QFETCH(QString, destinationPort);
        QFETCH(QString, protocol);

        UfwLogModel model(nullptr);
        model.addRawLogs({line});
        QCOMPARE(model.rowCount(), 1);
        const auto cell = [&model](int column) {
            return model.data(model.index(0, column)).toString();
        };
        if (!date.isEmpty()) {
            QCOMPARE(cell(LogListModel::DateColumn), date);
        }
        if (!time.isEmpty()) {
            QCOMPARE(cell(LogListModel::TimeColumn), time);
        }
        QCOMPARE(cell(LogListModel::InterfaceColumn), interface);
        QCOMPARE(cell(LogListModel::SourceAddressColumn), source);
        QCOMPARE(cell(LogListModel::SourcePortColumn), sourcePort);
        QCOMPARE(cell(LogListModel::DestinationAddressColumn), destination);
        QCOMPARE(cell(LogListModel::DestinationPortColumn), destinationPort);
        QCOMPARE(cell(LogListModel::ProtocolColumn), protocol);
    }

    void skipsOtherLines()
    {
        UfwLogModel model(nullptr);
        model.addRawLogs({QStringLiteral("-- Boot 1234 --"),
                          QStringLiteral("Dec 06 17:42:45 host kernel: [UFW BLOCK] IN=eth0 SRC=1.1.1.1 DST=2.2.2.2 PROTO=UDP SPT=3 DPT=4"),
                          QStringLiteral("Oct 27 10:00:00 host sshd[1]: Accepted")});
        QCOMPARE(model.rowCount(), 1);
    }
};

QTEST_GUILESS_MAIN(UfwLogModelTest)

#include "ufwlogmodeltest.moc"
