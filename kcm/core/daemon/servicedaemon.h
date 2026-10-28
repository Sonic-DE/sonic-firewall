// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#pragma once

#include "serviceprotocol.h"

#include <QHash>
#include <QObject>
#include <QPointer>
#include <QSet>
#include <QThread>

#include <functional>
#include <optional>

namespace Sonic::Ipc
{
class Connection;
class Server;
}

class ServiceWorker;

// Serves ServiceProtocol on a world-accessible socket. Each request is authorised, then run on one worker
// thread, so requests run one at a time in the order they were authorised.
class ServiceDaemon : public QObject
{
    Q_OBJECT
public:
    // Called exactly once on the main thread: std::nullopt = authorised; otherwise the Reply to send.
    using Decision = std::function<void(std::optional<ServiceProtocol::Reply>)>;
    using Authorizer = std::function<void(Sonic::Ipc::Connection *connection, Decision decide)>;
    // Runs on the worker thread.
    using Runner = std::function<ServiceProtocol::Reply(const ServiceProtocol::Request &request)>;
    static constexpr int maxConnections = 8;

    ServiceDaemon(const QString &socketPath, Authorizer authorizer, Runner runner, QObject *parent = nullptr);
    ~ServiceDaemon() override; // quits and waits for the worker thread, then deletes the worker
    bool start();

private:
    void handleConnection(Sonic::Ipc::Connection *connection);
    void handleManage(Sonic::Ipc::Connection *connection, const QByteArray &payload);
    void sendResult(Sonic::Ipc::Connection *connection, const ServiceProtocol::Reply &reply);
    void workerFinished(quint64 id, qint32 code, const QString &message);

    const QString m_socketPath;
    const Authorizer m_authorizer;
    Sonic::Ipc::Server *m_server = nullptr; // child of this
    QThread m_thread;
    ServiceWorker *m_worker = nullptr; // lives in m_thread
    QSet<Sonic::Ipc::Connection *> m_busy; // connections with a request in flight
    QHash<quint64, QPointer<Sonic::Ipc::Connection>> m_pending;
    quint64 m_nextId = 1;
};

class ServiceWorker : public QObject
{
    Q_OBJECT
public:
    explicit ServiceWorker(ServiceDaemon::Runner runner);
    void run(quint64 id, const ServiceProtocol::Request &request); // emits finished

Q_SIGNALS:
    void finished(quint64 id, qint32 code, const QString &message);

private:
    const ServiceDaemon::Runner m_runner;
};
