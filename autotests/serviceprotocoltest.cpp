// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#include "initsystem.h"
#include "serviceprotocol.h"

#include <QTest>

class ServiceProtocolTest : public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void constants()
    {
        // A change here changes the wire format; raise ServiceProtocol::version with it.
        QCOMPARE(ServiceProtocol::version, quint16(1));
        QCOMPARE(quint32(ServiceProtocol::Manage), quint32(1));
        QCOMPARE(quint32(ServiceProtocol::Result), quint32(2));
        QCOMPARE(ServiceProtocol::socketPath(), QStringLiteral("/run/sonic-firewall/service.sock"));
    }

    void requestRoundTrip()
    {
        const ServiceProtocol::Request request{QStringLiteral("firewalld"), true, false};
        const std::optional<ServiceProtocol::Request> decoded = ServiceProtocol::decodeRequest(ServiceProtocol::encode(request));
        QVERIFY(decoded);
        QCOMPARE(decoded->service, request.service);
        QCOMPARE(decoded->enable, request.enable);
        QCOMPARE(decoded->serviceOnly, request.serviceOnly);
    }

    void replyRoundTrip()
    {
        const ServiceProtocol::Reply reply{-104, QStringLiteral("Der Dienst „ufw“ fehlt – ✓")};
        const std::optional<ServiceProtocol::Reply> decoded = ServiceProtocol::decodeReply(ServiceProtocol::encode(reply));
        QVERIFY(decoded);
        QCOMPARE(decoded->code, reply.code);
        QCOMPARE(decoded->message, reply.message);
    }

    void rejectsBadPayloads()
    {
        const QByteArray request = ServiceProtocol::encode(ServiceProtocol::Request{QStringLiteral("ufw"), true, true});
        QVERIFY(!ServiceProtocol::decodeRequest(request.left(request.size() - 1)));
        QVERIFY(!ServiceProtocol::decodeRequest(request + QByteArray(1, '\0')));
        QVERIFY(!ServiceProtocol::decodeRequest(QByteArray()));

        const QByteArray reply = ServiceProtocol::encode(ServiceProtocol::Reply{0, QStringLiteral("ok")});
        QVERIFY(!ServiceProtocol::decodeReply(reply.left(reply.size() - 1)));
        QVERIFY(!ServiceProtocol::decodeReply(reply + QByteArray(1, '\0')));
        QVERIFY(!ServiceProtocol::decodeReply(QByteArray()));
    }

    void authorizationReply()
    {
        QVERIFY(!ServiceProtocol::authorizationReply(true, false));
        QVERIFY(!ServiceProtocol::authorizationReply(true, true));

        const std::optional<ServiceProtocol::Reply> noAgent = ServiceProtocol::authorizationReply(false, true);
        QVERIFY(noAgent);
        QCOMPARE(noAgent->code, qint32(InitSystem::NoAuthenticationAgent));
        QCOMPARE(noAgent->code, -106);
        QVERIFY(!noAgent->message.isEmpty());

        const std::optional<ServiceProtocol::Reply> denied = ServiceProtocol::authorizationReply(false, false);
        QVERIFY(denied);
        QCOMPARE(denied->code, 4);
    }
};

QTEST_GUILESS_MAIN(ServiceProtocolTest)

#include "serviceprotocoltest.moc"
