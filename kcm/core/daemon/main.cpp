// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

// sonic-firewall-service: starts, stops, enables and disables ufw and firewalld for the firewall settings,
// over Sonic IPC, after polkit authorises each request.

#include "initsystem.h"
#include "polkitauthority.h"
#include "servicedaemon.h"

#include <QCoreApplication>
#include <QDBusConnection>
#include <QDBusMetaType>
#include <QThread>

#include <KLocalizedString>

#include <Sonic/Logging/Logging>

#include <sys/socket.h>
#include <unistd.h>

SONIC_LOGGING_COMPONENT("org.sonicde.firewall.service")

namespace
{
constexpr int busAttempts = 30;

// Distros name the D-Bus service differently, so the service files' ordering can be wrong. Named probe
// connections are used because the default system bus connection is created once per process.
bool waitForSystemBus()
{
    for (int attempt = 1; attempt <= busAttempts; ++attempt) {
        const QString name = QStringLiteral("sonic-firewall-bus-probe-%1").arg(attempt);
        const bool up = QDBusConnection::connectToBus(QDBusConnection::SystemBus, name).isConnected();
        QDBusConnection::disconnectFromBus(name);
        if (up) {
            return true;
        }
        sonicInfo() << "waiting for the system bus, attempt" << attempt << "of" << busAttempts;
        QThread::sleep(1);
    }
    return false;
}
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    Sonic::Logging::install();

    if (geteuid() != 0) {
        sonicCritical() << "sonic-firewall-service must run as root";
        return 1;
    }

    qDBusRegisterMetaType<PolkitSubject>();
    qDBusRegisterMetaType<PolkitResult>();
    qDBusRegisterMetaType<QMap<QString, QString>>();

    if (!waitForSystemBus()) {
        sonicCritical() << "the system bus didn't come up; exiting so the service manager can restart the daemon";
        return 1;
    }

#ifdef SO_PEERPIDFD
    const bool pidfdBuilt = true;
#else
    const bool pidfdBuilt = false;
#endif
    sonicInfo() << "polkit subject forms: SO_PEERPIDFD compiled in:" << pidfdBuilt << "bus fd passing:"
                << QDBusConnection::systemBus().connectionCapabilities().testFlag(QDBusConnection::UnixFileDescriptorPassing);

    const auto authorizer = [](Sonic::Ipc::Connection *connection, ServiceDaemon::Decision decide) {
        PolkitAuthority::check(connection, QStringLiteral("org.sonicde.firewall.servicehelper.manage"), [decide](const PolkitDecision &decision) {
            if (!decision.reached) {
                decide(ServiceProtocol::Reply{InitSystem::AuthorizationUnavailable, i18n("Could not ask polkit for authorization: %1", decision.error)});
                return;
            }
            decide(ServiceProtocol::authorizationReply(decision.authorized, decision.challenge));
        });
    };
    const auto runner = [](const ServiceProtocol::Request &request) {
        QString message;
        const int code = InitSystem::manage(request.service, request.enable, request.serviceOnly, &message);
        return ServiceProtocol::Reply{code, message};
    };

    ServiceDaemon daemon(ServiceProtocol::socketPath(), authorizer, runner);
    if (!daemon.start()) {
        return 1;
    }
    return app.exec();
}
