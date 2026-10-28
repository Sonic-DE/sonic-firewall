// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#include "servicedaemon.h"
#include "initsystem.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLocalSocket>

#include <KLocalizedString>

#include <Sonic/Ipc/Connection>
#include <Sonic/Ipc/Server>
#include <Sonic/Logging/Log>

namespace
{
QString peerDescription(Sonic::Ipc::Connection *connection)
{
    const auto credentials = connection->peerCredentials();
    if (!credentials) {
        return QStringLiteral("unknown peer");
    }
    return QStringLiteral("uid %1 pid %2").arg(credentials->uid).arg(credentials->pid);
}
}

ServiceDaemon::ServiceDaemon(const QString &socketPath, Authorizer authorizer, Runner runner, QObject *parent)
    : QObject(parent)
    , m_socketPath(socketPath)
    , m_authorizer(std::move(authorizer))
    , m_server(new Sonic::Ipc::Server(this))
    , m_worker(new ServiceWorker(std::move(runner)))
{
    m_worker->moveToThread(&m_thread);
    // The objects live in different threads, so this connection is queued.
    connect(m_worker, &ServiceWorker::finished, this, &ServiceDaemon::workerFinished);
    m_thread.start();
}

ServiceDaemon::~ServiceDaemon()
{
    m_thread.quit();
    m_thread.wait();
    // The thread has stopped, so deleting the worker from here is safe.
    delete m_worker;
}

bool ServiceDaemon::start()
{
    const QString directory = QFileInfo(m_socketPath).absolutePath();
    QDir().mkpath(directory);
    // Users must be able to reach the socket.
    QFile::setPermissions(directory,
                          QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner | QFileDevice::ReadGroup | QFileDevice::ExeGroup
                              | QFileDevice::ReadOther | QFileDevice::ExeOther);

    if (!m_server->listen(m_socketPath, Sonic::Ipc::Server::Access::World, ServiceProtocol::version, ServiceProtocol::maxPayload)) {
        sonicCritical() << "cannot listen on" << m_socketPath << ":" << m_server->errorString();
        return false;
    }
    connect(m_server, &Sonic::Ipc::Server::newConnection, this, &ServiceDaemon::handleConnection);
    sonicInfo() << "serving" << m_socketPath;
    return true;
}

void ServiceDaemon::handleConnection(Sonic::Ipc::Connection *connection)
{
    // The socket is world-accessible and each request can raise a polkit prompt.
    if (m_server->connections().size() > maxConnections) {
        sonicWarning() << "too many connections; closing one from" << peerDescription(connection);
        connection->socket()->abort();
        return;
    }

    connect(connection, &Sonic::Ipc::Connection::frameReceived, connection, [this, connection](quint32 type, const QByteArray &payload) {
        if (type != ServiceProtocol::Manage) {
            sonicWarning() << "ignoring frame type" << type << "from" << peerDescription(connection);
            return;
        }
        handleManage(connection, payload);
    });
    connect(connection, &Sonic::Ipc::Connection::disconnected, this, [this, connection] {
        m_busy.remove(connection);
    });
}

void ServiceDaemon::handleManage(Sonic::Ipc::Connection *connection, const QByteArray &payload)
{
    if (m_busy.contains(connection)) {
        sonicWarning() << "a request is already in progress for" << peerDescription(connection);
        sendResult(connection, {InitSystem::InvalidArguments, i18n("A request is already in progress")});
        return;
    }

    const std::optional<ServiceProtocol::Request> request = ServiceProtocol::decodeRequest(payload);
    if (!request || !InitSystem::isAllowedService(request->service)) {
        sonicWarning() << "invalid request from" << peerDescription(connection);
        sendResult(connection, {InitSystem::InvalidArguments, i18n("Invalid arguments for the firewall service helper")});
        return;
    }

    sonicInfo() << "request:" << request->service << "enable:" << request->enable << "serviceOnly:" << request->serviceOnly << "from"
                << peerDescription(connection);
    m_busy.insert(connection);

    const QPointer<Sonic::Ipc::Connection> guard(connection);
    const ServiceProtocol::Request accepted = *request;
    m_authorizer(connection, [this, guard, connection, accepted](std::optional<ServiceProtocol::Reply> reply) {
        if (!guard) {
            m_busy.remove(connection);
            sonicInfo() << "the client left before authorization finished; dropping the request";
            return;
        }
        if (reply) {
            m_busy.remove(connection);
            sendResult(connection, *reply);
            return;
        }
        const quint64 id = m_nextId++;
        m_pending.insert(id, guard);
        // Queued calls to one object in one thread run one at a time in posting order.
        QMetaObject::invokeMethod(
            m_worker,
            [worker = m_worker, id, accepted] {
                worker->run(id, accepted);
            },
            Qt::QueuedConnection);
    });
}

void ServiceDaemon::sendResult(Sonic::Ipc::Connection *connection, const ServiceProtocol::Reply &reply)
{
    sonicInfo() << "result" << reply.code << "for" << peerDescription(connection);
    connection->send(ServiceProtocol::Result, ServiceProtocol::encode(reply));
}

void ServiceDaemon::workerFinished(quint64 id, qint32 code, const QString &message)
{
    const QPointer<Sonic::Ipc::Connection> connection = m_pending.take(id);
    if (!connection) {
        sonicInfo() << "the client left before request" << id << "finished; dropping the result" << code;
        return;
    }
    m_busy.remove(connection);
    sendResult(connection, {code, message});
}

ServiceWorker::ServiceWorker(ServiceDaemon::Runner runner)
    : m_runner(std::move(runner))
{
}

void ServiceWorker::run(quint64 id, const ServiceProtocol::Request &request)
{
    const ServiceProtocol::Reply reply = m_runner(request);
    Q_EMIT finished(id, reply.code, reply.message);
}

#include "moc_servicedaemon.cpp"
