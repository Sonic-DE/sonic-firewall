// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#include "initsystem.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTest>

Q_DECLARE_METATYPE(InitSystem::Operation)
Q_DECLARE_METATYPE(InitSystem::Type)

using InitSystem::Action;
using InitSystem::Operation;
using InitSystem::Type;

namespace
{
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

bool mkdir(const QString &path)
{
    return QDir().mkpath(path);
}

bool touch(const QString &path)
{
    if (!QDir().mkpath(QFileInfo(path).absolutePath())) {
        return false;
    }
    QFile file(path);
    return file.open(QIODevice::WriteOnly);
}

bool makeLink(const QString &target, const QString &path)
{
    return QDir().mkpath(QFileInfo(path).absolutePath()) && QFile::link(target, path);
}
}

class InitSystemTest : public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void installedQuery_data()
    {
        QTest::addColumn<Type>("type");
        QTest::addColumn<Operation>("expected");

        QTest::newRow("systemd") << Type::Systemd
                                 << run(QStringLiteral("systemctl"),
                                        {QStringLiteral("list-unit-files"), QStringLiteral("--no-legend"), QStringLiteral("--no-pager"), QStringLiteral("ufw.service")});
        QTest::newRow("openrc") << Type::OpenRC << run(QStringLiteral("rc-service"), {QStringLiteral("--exists"), QStringLiteral("ufw")});
        QTest::newRow("dinit") << Type::Dinit << run(QStringLiteral("dinitctl"), {QStringLiteral("--system"), QStringLiteral("status"), QStringLiteral("ufw")});
        QTest::newRow("s6") << Type::S6 << run(QStringLiteral("s6-rc-db"), {QStringLiteral("list"), QStringLiteral("all")});
        QTest::newRow("bsdrc") << Type::BsdRc << run(QStringLiteral("service"), {QStringLiteral("-l")});
        QTest::newRow("openbsdrc") << Type::OpenBsdRc << run(QStringLiteral("rcctl"), {QStringLiteral("ls"), QStringLiteral("all")});
        QTest::newRow("runit") << Type::Runit << Operation{};
        QTest::newRow("sysvinit") << Type::SysVinit << Operation{};
        QTest::newRow("unknown") << Type::Unknown << Operation{};
    }

    void installedQuery()
    {
        QFETCH(Type, type);
        QFETCH(Operation, expected);
        QCOMPARE(InitSystem::installedQuery(type, QStringLiteral("ufw")), expected);
    }

    void installedByFiles()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString root = dir.path();

        QVERIFY(!InitSystem::isServiceInstalled(Type::Runit, QStringLiteral("ufw"), root));
        QVERIFY(!InitSystem::isServiceInstalled(Type::SysVinit, QStringLiteral("ufw"), root));
        QVERIFY(!InitSystem::isServiceInstalled(Type::Unknown, QStringLiteral("ufw"), root));

        QVERIFY(mkdir(root + QStringLiteral("/etc/sv/ufw")));
        QVERIFY(touch(root + QStringLiteral("/etc/init.d/ufw")));
        QVERIFY(InitSystem::isServiceInstalled(Type::Runit, QStringLiteral("ufw"), root));
        QVERIFY(InitSystem::isServiceInstalled(Type::SysVinit, QStringLiteral("ufw"), root));
        QVERIFY(!InitSystem::isServiceInstalled(Type::Unknown, QStringLiteral("ufw"), root));
    }

    void openrcOperations()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString root = dir.path();
        QVERIFY(touch(root + QStringLiteral("/etc/init.d/ufw")));
        QVERIFY(mkdir(root + QStringLiteral("/etc/runlevels/default")));

        QCOMPARE(InitSystem::operations(Type::OpenRC, Action::Start, QStringLiteral("ufw"), root),
                 QList<Operation>{run(QStringLiteral("rc-service"), {QStringLiteral("ufw"), QStringLiteral("start")})});
        QVERIFY(InitSystem::operations(Type::OpenRC, Action::Stop, QStringLiteral("ufw"), root).isEmpty());
        QCOMPARE(InitSystem::operations(Type::OpenRC, Action::Enable, QStringLiteral("ufw"), root),
                 QList<Operation>{run(QStringLiteral("rc-update"), {QStringLiteral("add"), QStringLiteral("ufw"), QStringLiteral("default")})});
        QVERIFY(InitSystem::operations(Type::OpenRC, Action::Disable, QStringLiteral("ufw"), root).isEmpty());
        QVERIFY(!InitSystem::isServiceActive(Type::OpenRC, QStringLiteral("ufw"), root));

        // Dangling links: they point at the real /etc/init.d/ufw, outside the fake root.
        QVERIFY(makeLink(QStringLiteral("/etc/init.d/ufw-does-not-exist"), root + QStringLiteral("/run/openrc/started/ufw")));
        QVERIFY(makeLink(QStringLiteral("/etc/init.d/ufw-does-not-exist"), root + QStringLiteral("/etc/runlevels/default/ufw")));

        QVERIFY(InitSystem::operations(Type::OpenRC, Action::Start, QStringLiteral("ufw"), root).isEmpty());
        QCOMPARE(InitSystem::operations(Type::OpenRC, Action::Stop, QStringLiteral("ufw"), root),
                 QList<Operation>{run(QStringLiteral("rc-service"), {QStringLiteral("ufw"), QStringLiteral("stop")})});
        QVERIFY(InitSystem::operations(Type::OpenRC, Action::Enable, QStringLiteral("ufw"), root).isEmpty());
        QCOMPARE(InitSystem::operations(Type::OpenRC, Action::Disable, QStringLiteral("ufw"), root),
                 QList<Operation>{run(QStringLiteral("rc-update"), {QStringLiteral("del"), QStringLiteral("ufw"), QStringLiteral("default")})});
        QVERIFY(InitSystem::isServiceActive(Type::OpenRC, QStringLiteral("ufw"), root));
    }

    void openrcRunlevels_data()
    {
        QTest::addColumn<QStringList>("links");
        QTest::addColumn<QStringList>("levels");
        QTest::addColumn<QList<Operation>>("enable");
        QTest::addColumn<QList<Operation>>("disable");

        QTest::newRow("none") << QStringList{} << QStringList{}
                              << QList<Operation>{run(QStringLiteral("rc-update"), {QStringLiteral("add"), QStringLiteral("ufw"), QStringLiteral("default")})}
                              << QList<Operation>{};
        QTest::newRow("boot") << QStringList{QStringLiteral("boot")} << QStringList{QStringLiteral("boot")} << QList<Operation>{}
                              << QList<Operation>{run(QStringLiteral("rc-update"), {QStringLiteral("del"), QStringLiteral("ufw"), QStringLiteral("boot")})};
        QTest::newRow("boot and default") << QStringList{QStringLiteral("default"), QStringLiteral("boot")}
                                          << QStringList{QStringLiteral("boot"), QStringLiteral("default")} << QList<Operation>{}
                                          << QList<Operation>{run(QStringLiteral("rc-update"),
                                                                  {QStringLiteral("del"), QStringLiteral("ufw"), QStringLiteral("boot"), QStringLiteral("default")})};
    }

    void openrcRunlevels()
    {
        QFETCH(QStringList, links);
        QFETCH(QStringList, levels);
        QFETCH(QList<Operation>, enable);
        QFETCH(QList<Operation>, disable);

        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString root = dir.path();
        QVERIFY(InitSystem::openrcRunlevels(QStringLiteral("ufw"), root).isEmpty()); // no /etc/runlevels yet
        for (const QString &level : {QStringLiteral("boot"), QStringLiteral("default"), QStringLiteral("sysinit")}) {
            QVERIFY(mkdir(root + QStringLiteral("/etc/runlevels/") + level));
        }
        for (const QString &level : std::as_const(links)) {
            QVERIFY(makeLink(QStringLiteral("/etc/init.d/ufw"), root + QStringLiteral("/etc/runlevels/") + level + QStringLiteral("/ufw")));
        }

        QCOMPARE(InitSystem::openrcRunlevels(QStringLiteral("ufw"), root), levels);
        const QList<Operation> enableOperations = InitSystem::operations(Type::OpenRC, Action::Enable, QStringLiteral("ufw"), root);
        const QList<Operation> disableOperations = InitSystem::operations(Type::OpenRC, Action::Disable, QStringLiteral("ufw"), root);
        QCOMPARE(enableOperations, enable);
        QCOMPARE(disableOperations, disable);
        for (const Operation &operation : enableOperations + disableOperations) {
            QVERIFY(!operation.arguments.contains(QStringLiteral("-a")));
        }
    }

    void runitOperations_data()
    {
        QTest::addColumn<QString>("source");
        QTest::addColumn<QString>("active");
        QTest::newRow("void") << QStringLiteral("/etc/sv") << QStringLiteral("/var/service");
        QTest::newRow("artix") << QStringLiteral("/etc/runit/sv") << QStringLiteral("/run/runit/service");
    }

    void runitOperations()
    {
        QFETCH(QString, source);
        QFETCH(QString, active);

        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString root = dir.path();
        const QString sourceDir = root + source + QStringLiteral("/ufw");
        const QString linkPath = root + active + QStringLiteral("/ufw");
        QVERIFY(mkdir(sourceDir));
        QVERIFY(mkdir(root + active));

        QCOMPARE(InitSystem::operations(Type::Runit, Action::Start, QStringLiteral("ufw"), root), QList<Operation>{link(sourceDir, linkPath)});
        QCOMPARE(InitSystem::operations(Type::Runit, Action::Enable, QStringLiteral("ufw"), root), QList<Operation>{link(sourceDir, linkPath)});
        QVERIFY(InitSystem::operations(Type::Runit, Action::Stop, QStringLiteral("ufw"), root).isEmpty());
        QVERIFY(InitSystem::operations(Type::Runit, Action::Disable, QStringLiteral("ufw"), root).isEmpty());
        QVERIFY(!InitSystem::isServiceActive(Type::Runit, QStringLiteral("ufw"), root));

        QString error;
        QVERIFY2(InitSystem::applyFileOperation(link(sourceDir, linkPath), &error), qPrintable(error));
        QVERIFY(QFileInfo(linkPath).isSymbolicLink());
        QVERIFY(InitSystem::isServiceActive(Type::Runit, QStringLiteral("ufw"), root));

        QCOMPARE(InitSystem::operations(Type::Runit, Action::Start, QStringLiteral("ufw"), root),
                 QList<Operation>{run(QStringLiteral("sv"), {QStringLiteral("start"), linkPath})});
        QVERIFY(InitSystem::operations(Type::Runit, Action::Enable, QStringLiteral("ufw"), root).isEmpty());
        QCOMPARE(InitSystem::operations(Type::Runit, Action::Stop, QStringLiteral("ufw"), root),
                 QList<Operation>{run(QStringLiteral("sv"), {QStringLiteral("stop"), linkPath})});
        const QList<Operation> disable = InitSystem::operations(Type::Runit, Action::Disable, QStringLiteral("ufw"), root);
        QCOMPARE(disable, QList<Operation>{unlink(linkPath)});

        QVERIFY2(InitSystem::applyFileOperation(disable.first(), &error), qPrintable(error));
        QVERIFY(!QFileInfo(linkPath).isSymbolicLink());
        QVERIFY(!QFileInfo::exists(linkPath));
        QVERIFY(QFileInfo(sourceDir).isDir()); // QFile::remove() removed the link, not its target
        QVERIFY(!InitSystem::isServiceActive(Type::Runit, QStringLiteral("ufw"), root));
    }

    void unlinkRefusesRealDirectory()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString path = dir.path() + QStringLiteral("/var/service/ufw");
        QVERIFY(mkdir(path));

        QString error;
        QVERIFY(!InitSystem::applyFileOperation(unlink(path), &error));
        QVERIFY(!error.isEmpty());
        QVERIFY(QFileInfo(path).isDir());

        error.clear();
        QVERIFY(!InitSystem::applyFileOperation(run(QStringLiteral("true"), {}), &error));
        QVERIFY(!error.isEmpty());
    }

    void runitWithoutDirectories()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString root = dir.path();
        QVERIFY(InitSystem::runitActiveDirectory(root).isEmpty());
        QVERIFY(InitSystem::runitSourceDirectory(QStringLiteral("ufw"), root).isEmpty());

        QVERIFY(mkdir(root + QStringLiteral("/etc/sv/ufw")));
        QVERIFY(InitSystem::runitActiveDirectory(root).isEmpty());
        for (const Action action : {Action::Start, Action::Stop, Action::Enable, Action::Disable}) {
            QVERIFY(InitSystem::operations(Type::Runit, action, QStringLiteral("ufw"), root).isEmpty());
        }

        QTemporaryDir other;
        QVERIFY(other.isValid());
        QVERIFY(mkdir(other.path() + QStringLiteral("/var/service")));
        QVERIFY(InitSystem::runitSourceDirectory(QStringLiteral("ufw"), other.path()).isEmpty());
        for (const Action action : {Action::Start, Action::Stop, Action::Enable, Action::Disable}) {
            QVERIFY(InitSystem::operations(Type::Runit, action, QStringLiteral("ufw"), other.path()).isEmpty());
        }
    }

    void dinitOperations()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString root = dir.path();

        QCOMPARE(InitSystem::operations(Type::Dinit, Action::Start, QStringLiteral("ufw"), root),
                 QList<Operation>{run(QStringLiteral("dinitctl"), {QStringLiteral("--system"), QStringLiteral("start"), QStringLiteral("ufw")})});
        QCOMPARE(InitSystem::operations(Type::Dinit, Action::Stop, QStringLiteral("ufw"), root),
                 QList<Operation>{run(QStringLiteral("dinitctl"), {QStringLiteral("--system"), QStringLiteral("stop"), QStringLiteral("ufw")})});
        QCOMPARE(InitSystem::operations(Type::Dinit, Action::Enable, QStringLiteral("ufw"), root),
                 QList<Operation>{run(QStringLiteral("dinitctl"), {QStringLiteral("--system"), QStringLiteral("enable"), QStringLiteral("ufw")})});
        QVERIFY(InitSystem::operations(Type::Dinit, Action::Disable, QStringLiteral("ufw"), root).isEmpty());

        QVERIFY(makeLink(QStringLiteral("/etc/dinit.d/ufw"), root + QStringLiteral("/etc/dinit.d/boot.d/ufw")));
        QVERIFY(InitSystem::operations(Type::Dinit, Action::Enable, QStringLiteral("ufw"), root).isEmpty());
        QCOMPARE(InitSystem::operations(Type::Dinit, Action::Disable, QStringLiteral("ufw"), root),
                 QList<Operation>{run(QStringLiteral("dinitctl"), {QStringLiteral("--system"), QStringLiteral("disable"), QStringLiteral("ufw")})});
    }

    void sysvinitOperations()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString root = dir.path();

        QCOMPARE(InitSystem::operations(Type::SysVinit, Action::Start, QStringLiteral("ufw"), root),
                 QList<Operation>{run(root + QStringLiteral("/etc/init.d/ufw"), {QStringLiteral("start")})});
        QCOMPARE(InitSystem::operations(Type::SysVinit, Action::Stop, QStringLiteral("ufw"), root),
                 QList<Operation>{run(root + QStringLiteral("/etc/init.d/ufw"), {QStringLiteral("stop")})});
        QCOMPARE(InitSystem::operations(Type::SysVinit, Action::Enable, QStringLiteral("ufw"), root),
                 QList<Operation>{run(QStringLiteral("chkconfig"), {QStringLiteral("ufw"), QStringLiteral("on")})});
        QCOMPARE(InitSystem::operations(Type::SysVinit, Action::Disable, QStringLiteral("ufw"), root),
                 QList<Operation>{run(QStringLiteral("chkconfig"), {QStringLiteral("ufw"), QStringLiteral("off")})});

        QVERIFY(touch(root + QStringLiteral("/usr/sbin/update-rc.d")));
        QCOMPARE(InitSystem::operations(Type::SysVinit, Action::Enable, QStringLiteral("ufw"), root),
                 (QList<Operation>{run(QStringLiteral("update-rc.d"), {QStringLiteral("ufw"), QStringLiteral("defaults")}),
                                   run(QStringLiteral("update-rc.d"), {QStringLiteral("ufw"), QStringLiteral("enable")})}));
        QCOMPARE(InitSystem::operations(Type::SysVinit, Action::Disable, QStringLiteral("ufw"), root),
                 QList<Operation>{run(QStringLiteral("update-rc.d"), {QStringLiteral("ufw"), QStringLiteral("disable")})});
    }

    void fixedOperations_data()
    {
        QTest::addColumn<Type>("type");
        QTest::addColumn<int>("action");
        QTest::addColumn<QList<Operation>>("expected");

        const QString ufw = QStringLiteral("ufw");
        const auto add = [](const char *name, Type type, Action action, const QList<Operation> &expected) {
            QTest::newRow(name) << type << int(action) << expected;
        };
        add("systemd start", Type::Systemd, Action::Start, {run(QStringLiteral("systemctl"), {QStringLiteral("start"), ufw})});
        add("systemd stop", Type::Systemd, Action::Stop, {run(QStringLiteral("systemctl"), {QStringLiteral("stop"), ufw})});
        add("systemd enable", Type::Systemd, Action::Enable, {run(QStringLiteral("systemctl"), {QStringLiteral("enable"), ufw})});
        add("systemd disable", Type::Systemd, Action::Disable, {run(QStringLiteral("systemctl"), {QStringLiteral("disable"), ufw})});
        add("s6 start", Type::S6, Action::Start, {run(QStringLiteral("s6-rc"), {QStringLiteral("-u"), QStringLiteral("change"), ufw})});
        add("s6 stop", Type::S6, Action::Stop, {run(QStringLiteral("s6-rc"), {QStringLiteral("-d"), QStringLiteral("change"), ufw})});
        add("s6 enable",
            Type::S6,
            Action::Enable,
            {run(QStringLiteral("s6-service"), {QStringLiteral("add"), QStringLiteral("default"), ufw}), run(QStringLiteral("s6-db-reload"), {})});
        add("s6 disable",
            Type::S6,
            Action::Disable,
            {run(QStringLiteral("s6-service"), {QStringLiteral("delete"), QStringLiteral("default"), ufw}), run(QStringLiteral("s6-db-reload"), {})});
        add("bsdrc start", Type::BsdRc, Action::Start, {run(QStringLiteral("service"), {ufw, QStringLiteral("onestart")})});
        add("bsdrc stop", Type::BsdRc, Action::Stop, {run(QStringLiteral("service"), {ufw, QStringLiteral("onestop")})});
        add("bsdrc enable", Type::BsdRc, Action::Enable, {run(QStringLiteral("sysrc"), {QStringLiteral("ufw_enable=YES")})});
        add("bsdrc disable", Type::BsdRc, Action::Disable, {run(QStringLiteral("sysrc"), {QStringLiteral("ufw_enable=NO")})});
        add("openbsdrc start", Type::OpenBsdRc, Action::Start, {run(QStringLiteral("rcctl"), {QStringLiteral("-f"), QStringLiteral("start"), ufw})});
        add("openbsdrc stop", Type::OpenBsdRc, Action::Stop, {run(QStringLiteral("rcctl"), {QStringLiteral("stop"), ufw})});
        add("openbsdrc enable", Type::OpenBsdRc, Action::Enable, {run(QStringLiteral("rcctl"), {QStringLiteral("enable"), ufw})});
        add("openbsdrc disable", Type::OpenBsdRc, Action::Disable, {run(QStringLiteral("rcctl"), {QStringLiteral("disable"), ufw})});
        add("unknown start", Type::Unknown, Action::Start, {});
        add("unknown stop", Type::Unknown, Action::Stop, {});
        add("unknown enable", Type::Unknown, Action::Enable, {});
        add("unknown disable", Type::Unknown, Action::Disable, {});
    }

    void fixedOperations()
    {
        QFETCH(Type, type);
        QFETCH(int, action);
        QFETCH(QList<Operation>, expected);
        QCOMPARE(InitSystem::operations(type, Action(action), QStringLiteral("ufw")), expected);
    }

    void dinitActiveFallback()
    {
        if (!QStandardPaths::findExecutable(QStringLiteral("dinitctl")).isEmpty()) {
            QSKIP("dinitctl is installed, so the boot.d fallback isn't what decides");
        }
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const QString root = dir.path();
        QVERIFY(!InitSystem::isServiceActive(Type::Dinit, QStringLiteral("ufw"), root));
        QVERIFY(makeLink(QStringLiteral("/etc/dinit.d/ufw"), root + QStringLiteral("/etc/dinit.d/boot.d/ufw")));
        QVERIFY(InitSystem::isServiceActive(Type::Dinit, QStringLiteral("ufw"), root));
    }

    void allowedServices()
    {
        QVERIFY(InitSystem::isAllowedService(QStringLiteral("ufw")));
        QVERIFY(InitSystem::isAllowedService(QStringLiteral("firewalld")));
        for (const QString &service :
             {QStringLiteral("UFW"), QStringLiteral("ufw "), QStringLiteral("sshd"), QStringLiteral("../ufw"), QString()}) {
            QVERIFY2(!InitSystem::isAllowedService(service), qPrintable(service));
        }
    }

    void manageRejectsOtherServices()
    {
        QString message;
        QCOMPARE(InitSystem::manage(QStringLiteral("sshd"), true, false, &message), int(InitSystem::InvalidArguments));
        QVERIFY(!message.isEmpty());
    }

    void startTimeFromStat_data()
    {
        QTest::addColumn<QByteArray>("line");
        QTest::addColumn<bool>("valid");
        QTest::addColumn<quint64>("startTime");

        // Fields 3 to 22 after the command name; field 22 is 98765.
        const QByteArray tail = " S 1 1234 1234 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 98765 1000000 200 18446744073709551615";
        QTest::newRow("normal") << QByteArray("1234 (ufw)") + tail << true << quint64(98765);
        QTest::newRow("spaces and parenthesis in the name") << QByteArray("1234 (a) b)") + tail << true << quint64(98765);
        QTest::newRow("truncated") << QByteArray("1234 (ufw) S 1 1234 1234 0") << false << quint64(0);
        QTest::newRow("non-numeric") << QByteArray("1234 (ufw) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 abc 1000000") << false << quint64(0);
    }

    void startTimeFromStat()
    {
        QFETCH(QByteArray, line);
        QFETCH(bool, valid);
        QFETCH(quint64, startTime);
        const std::optional<quint64> parsed = InitSystem::startTimeFromStat(line);
        QCOMPARE(parsed.has_value(), valid);
        if (valid) {
            QCOMPARE(*parsed, startTime);
        }
    }
};

QTEST_GUILESS_MAIN(InitSystemTest)

#include "initsystemtest.moc"
