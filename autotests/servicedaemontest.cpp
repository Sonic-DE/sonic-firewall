// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#include "initsystem.h"
#include "servicedaemon.h"
#include "serviceprotocol.h"

#include <QMutex>
#include <QMutexLocker>
#include <QPointer>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>
#include <QThread>

#include <Sonic/Ipc/Client>
#include <Sonic/Ipc/Connection>

#include <algorithm>
#include <list>
#include <memory>

namespace
{
// A daemon with a fake authoriser and runner, on a socket in a temporary directory.
struct Fixture {
    QTemporaryDir dir;
    // Held decisions, answered by the test; used when holdDecisions is set.
    bool holdDecisions = false;
    std::optional<ServiceProtocol::Reply> decision; // what the authoriser answers when not holding
    QList<ServiceDaemon::Decision> held;
    int authorizations = 0;

    // Written by the runner on the worker thread.
    QMutex mutex;
    QList<ServiceProtocol::Request> runs;
    ServiceProtocol::Reply runnerReply{0, QString()};
    int inProgress = 0;
    int maxInProgress = 0;

    std::unique_ptr<ServiceDaemon> daemon;

    QString socketPath() const
    {
        return dir.filePath(QStringLiteral("sock/service.sock"));
    }

    bool start()
    {
        daemon = std::make_unique<ServiceDaemon>(
            socketPath(),
            [this](Sonic::Ipc::Connection *, ServiceDaemon::Decision decide) {
                ++authorizations;
                if (holdDecisions) {
                    held.append(decide);
                } else {
                    decide(decision);
                }
            },
            [this](const ServiceProtocol::Request &request) {
                ServiceProtocol::Reply reply;
                {
                    QMutexLocker locker(&mutex);
                    runs.append(request);
                    maxInProgress = std::max(maxInProgress, ++inProgress);
                    reply = runnerReply;
                }
                QThread::msleep(50);
                QMutexLocker locker(&mutex);
                --inProgress;
                return reply;
            });
        return daemon->start();
    }

    int runCount()
    {
        QMutexLocker locker(&mutex);
        return runs.size();
    }
};

struct TestClient {
    Sonic::Ipc::Client client{ServiceProtocol::version, ServiceProtocol::maxPayload};
    QPointer<Sonic::Ipc::Connection> connection;
    QList<ServiceProtocol::Reply> replies;
    bool disconnected = false;

    bool connectTo(const QString &path)
    {
        QSignalSpy spy(&client, &Sonic::Ipc::Client::connected);
        QObject::connect(&client, &Sonic::Ipc::Client::connected, &client, [this](Sonic::Ipc::Connection *c) {
            connection = c;
            QObject::connect(c, &Sonic::Ipc::Connection::frameReceived, c, [this](quint32 type, const QByteArray &payload) {
                if (type == ServiceProtocol::Result) {
                    if (const auto reply = ServiceProtocol::decodeReply(payload)) {
                        replies.append(*reply);
                    }
                }
            });
            QObject::connect(c, &Sonic::Ipc::Connection::disconnected, &client, [this] {
                disconnected = true;
            });
        });
        client.connectToServer(path);
        return spy.count() > 0 || spy.wait(2000);
    }

    bool send(const ServiceProtocol::Request &request)
    {
        return connection && connection->send(ServiceProtocol::Manage, ServiceProtocol::encode(request));
    }

    bool sendRaw(const QByteArray &payload)
    {
        return connection && connection->send(ServiceProtocol::Manage, payload);
    }
};

const ServiceProtocol::Request ufwOn{QStringLiteral("ufw"), true, false};
}

class ServiceDaemonTest : public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void authorisedRequestRuns()
    {
        Fixture fixture;
        QVERIFY(fixture.start());
        TestClient client;
        QVERIFY(client.connectTo(fixture.socketPath()));
        QVERIFY(client.send(ufwOn));

        QTRY_COMPARE_WITH_TIMEOUT(client.replies.size(), 1, 3000);
        QCOMPARE(client.replies.first().code, 0);
        QCOMPARE(fixture.runCount(), 1);
        QCOMPARE(fixture.runs.first().service, QStringLiteral("ufw"));
        QVERIFY(fixture.runs.first().enable);
        QVERIFY(!fixture.runs.first().serviceOnly);
    }

    void runnerResultIsSent()
    {
        Fixture fixture;
        fixture.runnerReply = {InitSystem::ServiceMissing, QStringLiteral("missing")};
        QVERIFY(fixture.start());
        TestClient client;
        QVERIFY(client.connectTo(fixture.socketPath()));
        QVERIFY(client.send(ufwOn));

        QTRY_COMPARE_WITH_TIMEOUT(client.replies.size(), 1, 3000);
        QCOMPARE(client.replies.first().code, -104);
        QCOMPARE(client.replies.first().message, QStringLiteral("missing"));
    }

    void deniedRequestDoesNotRun()
    {
        Fixture fixture;
        fixture.decision = ServiceProtocol::Reply{4, QStringLiteral("no")};
        QVERIFY(fixture.start());
        TestClient client;
        QVERIFY(client.connectTo(fixture.socketPath()));
        QVERIFY(client.send(ufwOn));

        QTRY_COMPARE_WITH_TIMEOUT(client.replies.size(), 1, 3000);
        QCOMPARE(client.replies.first().code, 4);
        QCOMPARE(client.replies.first().message, QStringLiteral("no"));
        QTest::qWait(100);
        QCOMPARE(fixture.runCount(), 0);
    }

    void invalidPayload()
    {
        Fixture fixture;
        QVERIFY(fixture.start());
        TestClient client;
        QVERIFY(client.connectTo(fixture.socketPath()));
        QVERIFY(client.sendRaw(QByteArrayLiteral("garbage")));

        QTRY_COMPARE_WITH_TIMEOUT(client.replies.size(), 1, 3000);
        QCOMPARE(client.replies.first().code, int(InitSystem::InvalidArguments));
        QCOMPARE(fixture.authorizations, 0);
    }

    void otherServiceRejected()
    {
        Fixture fixture;
        QVERIFY(fixture.start());
        TestClient client;
        QVERIFY(client.connectTo(fixture.socketPath()));
        QVERIFY(client.send({QStringLiteral("sshd"), true, false}));

        QTRY_COMPARE_WITH_TIMEOUT(client.replies.size(), 1, 3000);
        QCOMPARE(client.replies.first().code, int(InitSystem::InvalidArguments));
        QCOMPARE(fixture.authorizations, 0);
    }

    void oneRequestInFlightPerConnection()
    {
        Fixture fixture;
        fixture.holdDecisions = true;
        QVERIFY(fixture.start());
        TestClient client;
        QVERIFY(client.connectTo(fixture.socketPath()));
        QVERIFY(client.send(ufwOn));
        QTRY_COMPARE_WITH_TIMEOUT(fixture.held.size(), 1, 3000);
        QVERIFY(client.send(ufwOn));

        QTRY_COMPARE_WITH_TIMEOUT(client.replies.size(), 1, 3000);
        QCOMPARE(client.replies.first().code, int(InitSystem::InvalidArguments));
        QCOMPARE(fixture.held.size(), 1);

        fixture.held.first()(std::nullopt);
        QTRY_COMPARE_WITH_TIMEOUT(client.replies.size(), 2, 3000);
        QCOMPARE(client.replies.at(1).code, 0);
    }

    void clientLeavesBeforeAuthorisation()
    {
        Fixture fixture;
        fixture.holdDecisions = true;
        QVERIFY(fixture.start());
        {
            TestClient client;
            QVERIFY(client.connectTo(fixture.socketPath()));
            QVERIFY(client.send(ufwOn));
            QTRY_COMPARE_WITH_TIMEOUT(fixture.held.size(), 1, 3000);
            client.client.disconnectFromServer();
        }
        QTest::qWait(100); // the server deletes the connection
        fixture.held.first()(std::nullopt);
        QTest::qWait(200);
        QCOMPARE(fixture.runCount(), 0);
    }

    void connectionLimit()
    {
        Fixture fixture;
        QVERIFY(fixture.start());
        std::list<TestClient> clients;
        for (int i = 0; i < ServiceDaemon::maxConnections + 1; ++i) {
            clients.emplace_back();
            QVERIFY(clients.back().connectTo(fixture.socketPath()));
        }
        const auto closed = [&clients] {
            return int(std::count_if(clients.cbegin(), clients.cend(), [](const TestClient &client) {
                return client.disconnected;
            }));
        };
        QTRY_COMPARE_WITH_TIMEOUT(closed(), 1, 2000);
        QTest::qWait(200);
        QCOMPARE(closed(), 1);
    }

    void requestsRunOneAtATimeInOrder()
    {
        Fixture fixture;
        QVERIFY(fixture.start());
        TestClient first;
        TestClient second;
        QVERIFY(first.connectTo(fixture.socketPath()));
        QVERIFY(second.connectTo(fixture.socketPath()));

        QVERIFY(first.send({QStringLiteral("ufw"), true, false}));
        QTRY_COMPARE_WITH_TIMEOUT(fixture.authorizations, 1, 3000);
        QVERIFY(second.send({QStringLiteral("firewalld"), false, true}));

        QTRY_COMPARE_WITH_TIMEOUT(first.replies.size(), 1, 3000);
        QTRY_COMPARE_WITH_TIMEOUT(second.replies.size(), 1, 3000);
        QCOMPARE(fixture.runCount(), 2);
        QCOMPARE(fixture.runs.at(0).service, QStringLiteral("ufw"));
        QCOMPARE(fixture.runs.at(1).service, QStringLiteral("firewalld"));
        QCOMPARE(fixture.maxInProgress, 1);
    }
};

QTEST_GUILESS_MAIN(ServiceDaemonTest)

#include "servicedaemontest.moc"
