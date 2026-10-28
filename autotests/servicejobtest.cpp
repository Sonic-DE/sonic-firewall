// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#include "initsystem.h"
#include "servicejob.h"
#include "serviceprotocol.h"

#include <QLocalSocket>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>

#include <Sonic/Ipc/Connection>
#include <Sonic/Ipc/Server>

#include <functional>
#include <memory>

namespace
{
// What the fake daemon does with the Manage frame it receives.
using Handler = std::function<void(Sonic::Ipc::Connection *connection, const QByteArray &payload)>;

struct Outcome {
    int error = 0;
    QString errorText;
    int results = 0;
};
}

class ServiceJobTest : public QObject
{
    Q_OBJECT

    // Runs one job against a fake daemon (or none, when handler is null), and checks that it finishes once.
    Outcome runJob(const Handler &handler, quint16 serverVersion = ServiceProtocol::version)
    {
        Outcome outcome;
        QTemporaryDir dir;
        if (!dir.isValid()) {
            return outcome;
        }
        const QString path = dir.filePath(QStringLiteral("service.sock"));

        Sonic::Ipc::Server server;
        if (handler) {
            if (!server.listen(path, Sonic::Ipc::Server::Access::User, serverVersion)) {
                return outcome; // results stays 0, which fails the case
            }
            connect(&server, &Sonic::Ipc::Server::newConnection, this, [handler](Sonic::Ipc::Connection *connection) {
                connect(connection, &Sonic::Ipc::Connection::frameReceived, connection, [handler, connection](quint32 type, const QByteArray &payload) {
                    if (type == ServiceProtocol::Manage) {
                        handler(connection, payload);
                    }
                });
            });
        }

        auto job = std::make_unique<ServiceJob>(true, QStringLiteral("ufw"), true, ServiceJob::TestOptions{InitSystem::Type::OpenRC, path, 2000});
        // Reading error() after the wait mustn't race KJob's deleteLater().
        job->setAutoDelete(false);
        QSignalSpy spy(job.get(), &KJob::result);
        job->start();
        if (!spy.wait(5000)) {
            outcome.results = spy.count();
            return outcome;
        }
        QTest::qWait(200); // a late disconnected or timer must not emit a second result
        outcome.error = job->error();
        outcome.errorText = job->errorText();
        outcome.results = spy.count();
        return outcome;
    }

    static Handler replyWith(qint32 code, const QString &message)
    {
        return [code, message](Sonic::Ipc::Connection *connection, const QByteArray &) {
            connection->send(ServiceProtocol::Result, ServiceProtocol::encode(ServiceProtocol::Reply{code, message}));
        };
    }

private Q_SLOTS:
    void success()
    {
        std::optional<ServiceProtocol::Request> received;
        const Outcome outcome = runJob([&received](Sonic::Ipc::Connection *connection, const QByteArray &payload) {
            received = ServiceProtocol::decodeRequest(payload);
            connection->send(ServiceProtocol::Result, ServiceProtocol::encode(ServiceProtocol::Reply{0, QString()}));
        });
        QCOMPARE(outcome.results, 1);
        QVERIFY(received);
        QCOMPARE(received->service, QStringLiteral("ufw"));
        QVERIFY(received->enable);
        QVERIFY(received->serviceOnly);
        QCOMPARE(outcome.error, 0);
    }

    void failureCodePassesThrough()
    {
        const Outcome outcome = runJob(replyWith(InitSystem::ServiceMissing, QStringLiteral("missing")));
        QCOMPARE(outcome.results, 1);
        QCOMPARE(outcome.error, -104);
        QCOMPARE(outcome.errorText, QStringLiteral("missing"));
    }

    void denied()
    {
        const Outcome outcome = runJob(replyWith(4, QStringLiteral("denied")));
        QCOMPARE(outcome.results, 1);
        QCOMPARE(outcome.error, 4);
    }

    void authorizationUnavailableFallsBack()
    {
        const Outcome outcome = runJob(replyWith(InitSystem::AuthorizationUnavailable, QStringLiteral("no polkit")));
        QCOMPARE(outcome.results, 1);
        QCOMPARE(outcome.error, int(ServiceJob::FallbackError));
        QVERIFY(outcome.errorText.startsWith(QLatin1String("fallback:")));
    }

    void malformedReply()
    {
        const Outcome outcome = runJob([](Sonic::Ipc::Connection *connection, const QByteArray &) {
            connection->send(ServiceProtocol::Result, QByteArrayLiteral("garbage"));
        });
        QCOMPARE(outcome.results, 1);
        QCOMPARE(outcome.error, int(KJob::UserDefinedError));
        QVERIFY(outcome.errorText.contains(QLatin1String("invalid reply")));
    }

    void closedWithoutReply()
    {
        const Outcome outcome = runJob([](Sonic::Ipc::Connection *connection, const QByteArray &) {
            connection->socket()->disconnectFromServer();
        });
        QCOMPARE(outcome.results, 1);
        QCOMPARE(outcome.error, int(KJob::UserDefinedError));
        QVERIFY(outcome.errorText.contains(QLatin1String("closed the connection")));
    }

    void noAnswer()
    {
        const Outcome outcome = runJob([](Sonic::Ipc::Connection *, const QByteArray &) { });
        QCOMPARE(outcome.results, 1);
        QCOMPARE(outcome.error, int(KJob::UserDefinedError));
        QVERIFY(outcome.errorText.contains(QLatin1String("did not answer in time")));
    }

    void noDaemon()
    {
        const Outcome outcome = runJob(nullptr);
        QCOMPARE(outcome.results, 1);
        QCOMPARE(outcome.error, int(ServiceJob::FallbackError));
        QVERIFY(outcome.errorText.startsWith(QLatin1String("fallback:")));
    }

    void versionRejected()
    {
        const Outcome outcome = runJob(replyWith(0, QString()), ServiceProtocol::version + 1);
        QCOMPARE(outcome.results, 1);
        QCOMPARE(outcome.error, int(ServiceJob::FallbackError));
        QVERIFY2(outcome.errorText.startsWith(QLatin1String("fallback:")), qPrintable(outcome.errorText));
    }
};

QTEST_GUILESS_MAIN(ServiceJobTest)

#include "servicejobtest.moc"
