// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#include "polkitauthority.h"
#include "initsystem.h"

#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QDBusUnixFileDescriptor>
#include <QFile>
#include <QLocalSocket>

#include <Sonic/Ipc/Connection>
#include <Sonic/Logging/Log>

#include <cerrno>
#include <cstring>
#include <optional>

#include <sys/socket.h>
#include <unistd.h>

QDBusArgument &operator<<(QDBusArgument &argument, const PolkitSubject &subject)
{
    argument.beginStructure();
    argument << subject.kind << subject.details;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, PolkitSubject &subject)
{
    argument.beginStructure();
    argument >> subject.kind >> subject.details;
    argument.endStructure();
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const PolkitResult &result)
{
    argument.beginStructure();
    argument << result.authorized << result.challenge << result.details;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, PolkitResult &result)
{
    argument.beginStructure();
    argument >> result.authorized >> result.challenge >> result.details;
    argument.endStructure();
    return argument;
}

namespace
{
enum class SubjectForm { Pidfd, Pid };

struct Caller {
    quint32 pid = 0;
    qint32 uid = -1;
};

QString formName(SubjectForm form)
{
    return form == SubjectForm::Pidfd ? QStringLiteral("pidfd") : QStringLiteral("pid");
}

// The pidfd subject, or nullopt (with the reason in *why) when it can't be used here.
std::optional<PolkitSubject> pidfdSubject(Sonic::Ipc::Connection *connection, const Caller &caller, QString *why)
{
#ifdef SO_PEERPIDFD
    if (!QDBusConnection::systemBus().connectionCapabilities().testFlag(QDBusConnection::UnixFileDescriptorPassing)) {
        *why = QStringLiteral("the system bus can't pass file descriptors");
        return std::nullopt;
    }
    int fd = -1;
    socklen_t length = sizeof(fd);
    if (getsockopt(int(connection->socket()->socketDescriptor()), SOL_SOCKET, SO_PEERPIDFD, &fd, &length) != 0 || fd < 0) {
        *why = QStringLiteral("SO_PEERPIDFD failed: %1").arg(QString::fromLocal8Bit(strerror(errno)));
        return std::nullopt;
    }
    // QDBusUnixFileDescriptor copies the descriptor, so ours is closed straight away.
    const QDBusUnixFileDescriptor descriptor(fd);
    ::close(fd);
    return PolkitSubject{QStringLiteral("unix-process"),
                         {{QStringLiteral("pidfd"), QVariant::fromValue(descriptor)}, {QStringLiteral("uid"), QVariant::fromValue(caller.uid)}}};
#else
    Q_UNUSED(connection)
    Q_UNUSED(caller)
    *why = QStringLiteral("SO_PEERPIDFD isn't available in this build");
    return std::nullopt;
#endif
}

std::optional<PolkitSubject> pidSubject(const Caller &caller, QString *why)
{
    QFile stat(QStringLiteral("/proc/%1/stat").arg(caller.pid));
    if (!stat.open(QIODevice::ReadOnly)) {
        *why = QStringLiteral("cannot read %1").arg(stat.fileName());
        return std::nullopt;
    }
    const std::optional<quint64> startTime = InitSystem::startTimeFromStat(stat.readAll());
    if (!startTime) {
        *why = QStringLiteral("cannot parse %1").arg(stat.fileName());
        return std::nullopt;
    }
    return PolkitSubject{QStringLiteral("unix-process"),
                         {{QStringLiteral("pid"), QVariant::fromValue(caller.pid)},
                          {QStringLiteral("start-time"), QVariant::fromValue(*startTime)},
                          {QStringLiteral("uid"), QVariant::fromValue(caller.uid)}}};
}

void ask(Sonic::Ipc::Connection *connection,
         const QString &actionId,
         const Caller &caller,
         SubjectForm form,
         const PolkitSubject &subject,
         const std::function<void(const PolkitDecision &)> &done)
{
    QDBusMessage message = QDBusMessage::createMethodCall(QStringLiteral("org.freedesktop.PolicyKit1"),
                                                          QStringLiteral("/org/freedesktop/PolicyKit1/Authority"),
                                                          QStringLiteral("org.freedesktop.PolicyKit1.Authority"),
                                                          QStringLiteral("CheckAuthorization"));
    // Flag 1 allows user interaction, so the caller's session agent prompts.
    message << QVariant::fromValue(subject) << actionId << QVariant::fromValue(QMap<QString, QString>()) << quint32(1) << QString();
    // The user may take minutes to answer the prompt.
    const QDBusPendingCall call = QDBusConnection::systemBus().asyncCall(message, 300000);
    auto *watcher = new QDBusPendingCallWatcher(call, connection);
    QObject::connect(watcher, &QDBusPendingCallWatcher::finished, connection, [connection, actionId, caller, form, done](QDBusPendingCallWatcher *self) {
        self->deleteLater();
        const QDBusPendingReply<PolkitResult> reply = *self;
        if (reply.isValid()) {
            const PolkitResult result = reply.value();
            sonicInfo() << "polkit:" << actionId << "uid" << caller.uid << "pid" << caller.pid << "subject" << formName(form) << "authorized:" << result.authorized
                        << "challenge:" << result.challenge;
            done({.reached = true, .authorized = result.authorized, .challenge = result.challenge, .error = QString()});
            return;
        }

        const QDBusError error = reply.error();
        if (error.type() == QDBusError::NoReply || error.type() == QDBusError::Timeout) {
            // The prompt was shown but not answered in time; asking again through KAuth would prompt twice.
            sonicInfo() << "polkit: no answer for uid" << caller.uid << "pid" << caller.pid << "subject" << formName(form) << ":" << error.message();
            done({.reached = true, .authorized = false, .challenge = false, .error = QString()});
            return;
        }
        if (form == SubjectForm::Pidfd) {
            // polkit older than 121 doesn't know the pidfd subject.
            sonicWarning() << "polkit rejected the pidfd subject:" << error.message() << "; retrying with the pid subject";
            QString why;
            const std::optional<PolkitSubject> fallback = pidSubject(caller, &why);
            if (!fallback) {
                sonicWarning() << "polkit: cannot build the pid subject:" << why;
                done({.reached = false, .error = why});
                return;
            }
            ask(connection, actionId, caller, SubjectForm::Pid, *fallback, done);
            return;
        }
        sonicWarning() << "polkit: CheckAuthorization failed for uid" << caller.uid << "pid" << caller.pid << ":" << error.message();
        done({.reached = false, .error = error.message()});
    });
}
}

namespace PolkitAuthority
{
void check(Sonic::Ipc::Connection *connection, const QString &actionId, std::function<void(const PolkitDecision &)> done)
{
    const auto credentials = connection->peerCredentials();
    if (!credentials || credentials->pid <= 0) {
        sonicWarning() << "polkit: the caller can't be identified";
        done({.reached = false, .error = QStringLiteral("the caller can't be identified")});
        return;
    }
    const Caller caller{quint32(credentials->pid), qint32(credentials->uid)};

    QString why;
    if (const std::optional<PolkitSubject> subject = pidfdSubject(connection, caller, &why)) {
        ask(connection, actionId, caller, SubjectForm::Pidfd, *subject, done);
        return;
    }
    sonicWarning() << "polkit: not using the pidfd subject:" << why;
    const std::optional<PolkitSubject> subject = pidSubject(caller, &why);
    if (!subject) {
        sonicWarning() << "polkit: cannot build the pid subject:" << why;
        done({.reached = false, .error = why});
        return;
    }
    ask(connection, actionId, caller, SubjectForm::Pid, *subject, done);
}
}
