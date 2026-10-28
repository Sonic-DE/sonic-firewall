// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#include "initsystem.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QProcessEnvironment>
#include <QStandardPaths>

#include <KLocalizedString>

#include <Sonic/Logging/Log>

#include <algorithm>

namespace InitSystem
{
namespace
{
// Root-side commands: the installed query and each step.
constexpr int rootStartMs = 10000;
constexpr int rootFinishMs = 60000;
// GUI-thread checks in isServiceActive.
constexpr int quietMs = 5000;

// QFileInfo::exists() is false for a dangling symlink, and fake-root links point outside the root.
bool entryExists(const QString &path)
{
    return QFileInfo(path).isSymbolicLink() || QFileInfo::exists(path);
}

QString resolveProgram(const QString &program)
{
    QString path = QStandardPaths::findExecutable(program, systemBinaryPaths());
    if (path.isEmpty()) {
        path = QStandardPaths::findExecutable(program);
    }
    return path;
}

QString describe(const Operation &operation)
{
    switch (operation.kind) {
    case Operation::Kind::Run:
        return (QStringList{operation.program} + operation.arguments).join(u' ');
    case Operation::Kind::Link:
        return QStringLiteral("link %1 -> %2").arg(operation.linkPath, operation.linkTarget);
    case Operation::Kind::Unlink:
        return QStringLiteral("unlink %1").arg(operation.linkPath);
    }
    return {};
}

QString actionName(Action action)
{
    switch (action) {
    case Action::Start:
        return QStringLiteral("Start");
    case Action::Stop:
        return QStringLiteral("Stop");
    case Action::Enable:
        return QStringLiteral("Enable");
    case Action::Disable:
        return QStringLiteral("Disable");
    }
    return {};
}

Operation run(const QString &program, const QStringList &arguments)
{
    Operation operation;
    operation.program = program;
    operation.arguments = arguments;
    return operation;
}

Operation link(const QString &target, const QString &path)
{
    Operation operation;
    operation.kind = Operation::Kind::Link;
    operation.linkTarget = target;
    operation.linkPath = path;
    return operation;
}

Operation unlink(const QString &path)
{
    Operation operation;
    operation.kind = Operation::Kind::Unlink;
    operation.linkPath = path;
    return operation;
}

QProcessEnvironment rootEnvironment()
{
    QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
    environment.insert(QStringLiteral("PATH"), systemBinaryPaths().join(u':'));
    return environment;
}

struct ProcessResult {
    bool found = false;
    bool started = false;
    bool timedOut = false;
    bool normalExit = false;
    int exitCode = -1;
    QByteArray standardOutput;
    QByteArray standardError;

    bool succeeded() const
    {
        return normalExit && exitCode == 0;
    }
};

ProcessResult runProcess(const QString &program, const QStringList &arguments, int startMs, int finishMs, bool rootEnvironmentPath)
{
    ProcessResult result;
    const QString path = resolveProgram(program);
    if (path.isEmpty()) {
        return result;
    }
    result.found = true;

    QProcess process;
    if (rootEnvironmentPath) {
        process.setProcessEnvironment(rootEnvironment());
    }
    process.start(path, arguments);
    if (!process.waitForStarted(startMs)) {
        return result;
    }
    result.started = true;
    if (!process.waitForFinished(finishMs)) {
        result.timedOut = true;
        process.kill();
        process.waitForFinished(1000);
        return result;
    }
    result.normalExit = process.exitStatus() == QProcess::NormalExit;
    result.exitCode = process.exitCode();
    result.standardOutput = process.readAllStandardOutput();
    result.standardError = process.readAllStandardError();
    return result;
}

bool runQuiet(const QString &program, const QStringList &arguments)
{
    const ProcessResult result = runProcess(program, arguments, quietMs, quietMs, false);
    sonicDebug() << "check" << program << arguments << "found:" << result.found << "started:" << result.started << "timed out:" << result.timedOut
                 << "exit code:" << result.exitCode << "ok:" << result.succeeded();
    return result.succeeded();
}

QStringList outputLines(const QByteArray &output)
{
    QStringList lines;
    const QStringList rawLines = QString::fromLocal8Bit(output).split(u'\n', Qt::SkipEmptyParts);
    for (const QString &line : rawLines) {
        lines.append(line.trimmed());
    }
    return lines;
}
}

QStringList systemBinaryPaths()
{
    return {QStringLiteral("/sbin"),
            QStringLiteral("/usr/sbin"),
            QStringLiteral("/bin"),
            QStringLiteral("/usr/bin"),
            QStringLiteral("/usr/local/sbin"),
            QStringLiteral("/usr/local/bin")};
}

Type detect()
{
    const Type type = Sonic::InitInfo::serviceManager();
    sonicDebug() << "service manager:" << Sonic::InitInfo::name(type);
    return type;
}

QString typeName(Type type)
{
    return Sonic::InitInfo::name(type);
}

Operation installedQuery(Type type, const QString &service, const QString &root)
{
    Q_UNUSED(root)
    switch (type) {
    case Type::Systemd:
        return run(QStringLiteral("systemctl"), {QStringLiteral("list-unit-files"), QStringLiteral("--no-legend"), QStringLiteral("--no-pager"), service + QStringLiteral(".service")});
    case Type::OpenRC:
        return run(QStringLiteral("rc-service"), {QStringLiteral("--exists"), service});
    case Type::Dinit:
        return run(QStringLiteral("dinitctl"), {QStringLiteral("--system"), QStringLiteral("status"), service});
    case Type::S6:
        return run(QStringLiteral("s6-rc-db"), {QStringLiteral("list"), QStringLiteral("all")});
    case Type::BsdRc:
        return run(QStringLiteral("service"), {QStringLiteral("-l")});
    case Type::OpenBsdRc:
        return run(QStringLiteral("rcctl"), {QStringLiteral("ls"), QStringLiteral("all")});
    case Type::Runit:
    case Type::SysVinit:
    case Type::Unknown:
        break;
    }
    return {};
}

bool isServiceInstalled(Type type, const QString &service, const QString &root)
{
    switch (type) {
    case Type::Runit:
        return !runitSourceDirectory(service, root).isEmpty();
    case Type::SysVinit:
        return entryExists(root + QStringLiteral("/etc/init.d/") + service);
    case Type::Unknown:
        return false;
    default:
        break;
    }

    const Operation query = installedQuery(type, service, root);
    const ProcessResult result = runProcess(query.program, query.arguments, rootStartMs, rootFinishMs, true);
    if (!result.found) {
        sonicWarning() << "cannot check whether" << service << "is installed:" << query.program << "was not found";
        return false;
    }

    bool installed = false;
    if (result.normalExit) {
        const QStringList lines = outputLines(result.standardOutput);
        switch (type) {
        case Type::Systemd:
            installed = std::any_of(lines.cbegin(), lines.cend(), [&service](const QString &line) {
                return line.startsWith(service + QStringLiteral(".service"));
            });
            break;
        case Type::OpenRC:
        case Type::Dinit:
            installed = result.exitCode == 0;
            break;
        case Type::S6:
        case Type::BsdRc:
        case Type::OpenBsdRc:
            installed = lines.contains(service);
            break;
        default:
            break;
        }
    }
    sonicInfo() << "installed query" << describe(query) << "normal exit:" << result.normalExit << "exit code:" << result.exitCode
                << "timed out:" << result.timedOut << "installed:" << installed;
    return installed;
}

QString runitSourceDirectory(const QString &service, const QString &root)
{
    for (const QString &directory : {QStringLiteral("/etc/runit/sv/"), QStringLiteral("/etc/sv/")}) {
        const QString path = root + directory + service;
        if (QFileInfo(path).isDir()) {
            return path;
        }
    }
    return {};
}

QString runitActiveDirectory(const QString &root)
{
    for (const QString &directory : {QStringLiteral("/run/runit/service"), QStringLiteral("/var/service"), QStringLiteral("/etc/service"), QStringLiteral("/service")}) {
        const QString path = root + directory;
        if (QFileInfo(path).isDir()) {
            return path;
        }
    }
    return {};
}

QStringList openrcRunlevels(const QString &service, const QString &root)
{
    const QString runlevels = root + QStringLiteral("/etc/runlevels");
    QStringList result;
    const QStringList levels = QDir(runlevels).entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
    for (const QString &level : levels) {
        if (entryExists(runlevels + u'/' + level + u'/' + service)) {
            result.append(level);
        }
    }
    return result;
}

QList<Operation> operations(Type type, Action action, const QString &service, const QString &root)
{
    switch (type) {
    case Type::Systemd: {
        static const QStringList verbs{QStringLiteral("start"), QStringLiteral("stop"), QStringLiteral("enable"), QStringLiteral("disable")};
        return {run(QStringLiteral("systemctl"), {verbs.at(int(action)), service})};
    }
    case Type::OpenRC: {
        const bool started = entryExists(root + QStringLiteral("/run/openrc/started/") + service);
        switch (action) {
        case Action::Start:
            if (started) {
                return {};
            }
            return {run(QStringLiteral("rc-service"), {service, QStringLiteral("start")})};
        case Action::Stop:
            if (!started) {
                return {};
            }
            return {run(QStringLiteral("rc-service"), {service, QStringLiteral("stop")})};
        case Action::Enable:
            if (!openrcRunlevels(service, root).isEmpty()) {
                return {};
            }
            return {run(QStringLiteral("rc-update"), {QStringLiteral("add"), service, QStringLiteral("default")})};
        case Action::Disable: {
            const QStringList levels = openrcRunlevels(service, root);
            if (levels.isEmpty()) {
                return {};
            }
            return {run(QStringLiteral("rc-update"), QStringList{QStringLiteral("del"), service} + levels)};
        }
        }
        break;
    }
    case Type::Runit: {
        const QString active = runitActiveDirectory(root);
        const QString source = runitSourceDirectory(service, root);
        if (active.isEmpty() || source.isEmpty()) {
            return {};
        }
        const QString linkPath = active + u'/' + service;
        const bool linked = entryExists(linkPath);
        switch (action) {
        case Action::Start:
            if (linked) {
                return {run(QStringLiteral("sv"), {QStringLiteral("start"), linkPath})};
            }
            return {link(source, linkPath)};
        case Action::Stop:
            if (linked) {
                return {run(QStringLiteral("sv"), {QStringLiteral("stop"), linkPath})};
            }
            return {};
        case Action::Enable:
            if (linked) {
                return {};
            }
            return {link(source, linkPath)};
        case Action::Disable:
            if (linked) {
                return {unlink(linkPath)};
            }
            return {};
        }
        break;
    }
    case Type::S6:
        switch (action) {
        case Action::Start:
            return {run(QStringLiteral("s6-rc"), {QStringLiteral("-u"), QStringLiteral("change"), service})};
        case Action::Stop:
            return {run(QStringLiteral("s6-rc"), {QStringLiteral("-d"), QStringLiteral("change"), service})};
        case Action::Enable:
            return {run(QStringLiteral("s6-service"), {QStringLiteral("add"), QStringLiteral("default"), service}), run(QStringLiteral("s6-db-reload"), {})};
        case Action::Disable:
            return {run(QStringLiteral("s6-service"), {QStringLiteral("delete"), QStringLiteral("default"), service}), run(QStringLiteral("s6-db-reload"), {})};
        }
        break;
    case Type::Dinit: {
        const bool enabled = entryExists(root + QStringLiteral("/etc/dinit.d/boot.d/") + service);
        switch (action) {
        case Action::Start:
            return {run(QStringLiteral("dinitctl"), {QStringLiteral("--system"), QStringLiteral("start"), service})};
        case Action::Stop:
            return {run(QStringLiteral("dinitctl"), {QStringLiteral("--system"), QStringLiteral("stop"), service})};
        case Action::Enable:
            if (enabled) {
                return {};
            }
            return {run(QStringLiteral("dinitctl"), {QStringLiteral("--system"), QStringLiteral("enable"), service})};
        case Action::Disable:
            if (!enabled) {
                return {};
            }
            return {run(QStringLiteral("dinitctl"), {QStringLiteral("--system"), QStringLiteral("disable"), service})};
        }
        break;
    }
    case Type::SysVinit: {
        const bool updateRcD = entryExists(root + QStringLiteral("/usr/sbin/update-rc.d")) || entryExists(root + QStringLiteral("/sbin/update-rc.d"));
        switch (action) {
        case Action::Start:
            return {run(root + QStringLiteral("/etc/init.d/") + service, {QStringLiteral("start")})};
        case Action::Stop:
            return {run(root + QStringLiteral("/etc/init.d/") + service, {QStringLiteral("stop")})};
        case Action::Enable:
            if (updateRcD) {
                return {run(QStringLiteral("update-rc.d"), {service, QStringLiteral("defaults")}), run(QStringLiteral("update-rc.d"), {service, QStringLiteral("enable")})};
            }
            return {run(QStringLiteral("chkconfig"), {service, QStringLiteral("on")})};
        case Action::Disable:
            if (updateRcD) {
                return {run(QStringLiteral("update-rc.d"), {service, QStringLiteral("disable")})};
            }
            return {run(QStringLiteral("chkconfig"), {service, QStringLiteral("off")})};
        }
        break;
    }
    case Type::BsdRc:
        switch (action) {
        case Action::Start:
            return {run(QStringLiteral("service"), {service, QStringLiteral("onestart")})};
        case Action::Stop:
            return {run(QStringLiteral("service"), {service, QStringLiteral("onestop")})};
        case Action::Enable:
            return {run(QStringLiteral("sysrc"), {service + QStringLiteral("_enable=YES")})};
        case Action::Disable:
            return {run(QStringLiteral("sysrc"), {service + QStringLiteral("_enable=NO")})};
        }
        break;
    case Type::OpenBsdRc:
        switch (action) {
        case Action::Start:
            return {run(QStringLiteral("rcctl"), {QStringLiteral("-f"), QStringLiteral("start"), service})};
        case Action::Stop:
            return {run(QStringLiteral("rcctl"), {QStringLiteral("stop"), service})};
        case Action::Enable:
            return {run(QStringLiteral("rcctl"), {QStringLiteral("enable"), service})};
        case Action::Disable:
            return {run(QStringLiteral("rcctl"), {QStringLiteral("disable"), service})};
        }
        break;
    case Type::Unknown:
        break;
    }
    return {};
}

bool applyFileOperation(const Operation &operation, QString *error)
{
    QString failure;
    switch (operation.kind) {
    case Operation::Kind::Run:
        failure = QStringLiteral("not a file operation");
        break;
    case Operation::Kind::Link:
        if (!QFile::link(operation.linkTarget, operation.linkPath)) {
            failure = QStringLiteral("cannot create link %1 -> %2").arg(operation.linkPath, operation.linkTarget);
        }
        break;
    case Operation::Kind::Unlink:
        if (!QFileInfo(operation.linkPath).isSymbolicLink()) {
            failure = QStringLiteral("%1 is not a symbolic link").arg(operation.linkPath);
        } else if (!QFile::remove(operation.linkPath)) {
            failure = QStringLiteral("cannot remove link %1").arg(operation.linkPath);
        }
        break;
    }

    if (!failure.isEmpty()) {
        sonicWarning() << failure;
        if (error) {
            *error = failure;
        }
        return false;
    }
    sonicDebug() << "done:" << describe(operation);
    return true;
}

bool isServiceActive(Type type, const QString &service, const QString &root)
{
    switch (type) {
    case Type::Systemd:
        return runQuiet(QStringLiteral("systemctl"), {QStringLiteral("is-active"), QStringLiteral("--quiet"), service});
    case Type::OpenRC:
        return entryExists(root + QStringLiteral("/run/openrc/started/") + service);
    case Type::Runit: {
        const QString active = runitActiveDirectory(root);
        return !active.isEmpty() && entryExists(active + u'/' + service);
    }
    case Type::S6: {
        // stdout is needed here, so this uses runProcess directly with the same limits as runQuiet.
        const ProcessResult result = runProcess(QStringLiteral("s6-rc"), {QStringLiteral("-a"), QStringLiteral("list")}, quietMs, quietMs, false);
        const QStringList lines = outputLines(result.standardOutput);
        const bool active = result.succeeded() && (lines.contains(service) || lines.contains(service + QStringLiteral("-srv")));
        sonicDebug() << "check s6-rc -a list for" << service << "ok:" << result.succeeded() << "active:" << active;
        return active;
    }
    case Type::Dinit:
        return runQuiet(QStringLiteral("dinitctl"), {QStringLiteral("--system"), QStringLiteral("is-started"), service})
            || entryExists(root + QStringLiteral("/etc/dinit.d/boot.d/") + service);
    case Type::SysVinit:
        return runQuiet(root + QStringLiteral("/etc/init.d/") + service, {QStringLiteral("status")});
    case Type::BsdRc:
        return runQuiet(QStringLiteral("service"), {service, QStringLiteral("status")});
    case Type::OpenBsdRc:
        return runQuiet(QStringLiteral("rcctl"), {QStringLiteral("check"), service});
    case Type::Unknown:
        break;
    }
    return false;
}

bool isServiceActive(const QString &service)
{
    return isServiceActive(detect(), service);
}

bool isAllowedService(const QString &service)
{
    return service == QLatin1String("ufw") || service == QLatin1String("firewalld");
}

std::optional<quint64> startTimeFromStat(const QByteArray &statLine)
{
    const qsizetype close = statLine.lastIndexOf(')');
    if (close < 0) {
        return std::nullopt;
    }
    // Field 3 (state) is the first token after the command name, so field 22 is the 20th.
    const QList<QByteArray> fields = statLine.mid(close + 1).simplified().split(' ');
    constexpr qsizetype startTimeIndex = 22 - 3;
    if (fields.size() <= startTimeIndex) {
        return std::nullopt;
    }
    bool ok = false;
    const quint64 value = fields.at(startTimeIndex).toULongLong(&ok);
    if (!ok) {
        return std::nullopt;
    }
    return value;
}

int manage(const QString &service, bool enable, bool serviceOnly, QString *message)
{
    const auto fail = [message](int status, const QString &text) {
        if (message) {
            *message = text;
        }
        return status;
    };

    if (!isAllowedService(service)) {
        sonicWarning() << "refusing to manage" << service;
        return fail(InvalidArguments, i18n("Invalid arguments for the firewall service helper"));
    }

    const Type type = detect();
    sonicInfo() << "manage" << service << "enable:" << enable << "serviceOnly:" << serviceOnly << "init:" << typeName(type);
    if (type == Type::Unknown) {
        return fail(UnknownInit, i18n("Could not detect the init system"));
    }
    if (!isServiceInstalled(type, service)) {
        return fail(ServiceMissing, i18n("The %1 service is not installed for %2", service, typeName(type)));
    }
    if (type == Type::Runit && (runitActiveDirectory().isEmpty() || runitSourceDirectory(service).isEmpty())) {
        return fail(OperationFailed, i18n("No runit service directory was found"));
    }

    QList<Action> steps;
    if (enable) {
        steps = serviceOnly ? QList<Action>{Action::Enable} : QList<Action>{Action::Start, Action::Enable};
    } else {
        steps = serviceOnly ? QList<Action>{Action::Disable} : QList<Action>{Action::Stop, Action::Disable};
    }

    for (const Action step : std::as_const(steps)) {
        // Asked right before the step runs, so it sees the previous step's changes.
        const QList<Operation> stepOperations = operations(type, step, service);
        if (stepOperations.isEmpty()) {
            sonicInfo().noquote() << actionName(step) + QStringLiteral(": nothing to do");
            continue;
        }
        for (const Operation &operation : stepOperations) {
            sonicInfo().noquote() << actionName(step) + QStringLiteral(":") << describe(operation);
            if (operation.kind != Operation::Kind::Run) {
                QString error;
                if (!applyFileOperation(operation, &error)) {
                    return fail(OperationFailed, error);
                }
                continue;
            }

            const ProcessResult result = runProcess(operation.program, operation.arguments, rootStartMs, rootFinishMs, true);
            if (!result.found) {
                sonicWarning() << operation.program << "was not found";
                return fail(OperationFailed, i18n("%1 was not found", operation.program));
            }
            if (result.timedOut) {
                sonicWarning() << operation.program << "timed out";
                return fail(OperationFailed, i18n("%1 timed out", operation.program));
            }
            if (!result.succeeded()) {
                QString output = QString::fromLocal8Bit(result.standardError).trimmed();
                if (output.isEmpty()) {
                    output = QString::fromLocal8Bit(result.standardOutput).trimmed();
                }
                if (output.isEmpty()) {
                    output = i18n("exit code %1", result.exitCode);
                }
                sonicWarning() << "failed:" << describe(operation) << "started:" << result.started << "normal exit:" << result.normalExit
                               << "exit code:" << result.exitCode;
                return fail(OperationFailed, i18n("Command '%1' failed: %2", operation.program + u' ' + operation.arguments.join(u' '), output));
            }
            sonicInfo() << "succeeded:" << describe(operation) << "exit code:" << result.exitCode;
        }
    }
    return Ok;
}
}
