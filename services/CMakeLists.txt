# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

# Service files for sonic-firewall-service. The top-level CMakeLists.txt detects the init systems
# (or MANUAL_INITS lets packagers choose them); SPLIT_BUILD installs all of them as separate components.
include(GNUInstallDirs)
option(SPLIT_BUILD "Generate separate installation components for distros that support multiple init systems and split them in to separate packages" OFF)

# systemd
configure_file(systemd/sonic-firewall-service.service.in systemd/sonic-firewall-service.service @ONLY)
if(SPLIT_BUILD)
    install(
        FILES "${CMAKE_CURRENT_BINARY_DIR}/systemd/sonic-firewall-service.service"
        DESTINATION "${KDE_INSTALL_SYSTEMDUNITDIR}/system"
        COMPONENT systemd
    )
elseif(SYSTEMD_FOUND)
    install(
        FILES "${CMAKE_CURRENT_BINARY_DIR}/systemd/sonic-firewall-service.service"
        DESTINATION "${KDE_INSTALL_SYSTEMDUNITDIR}/system"
    )
endif()

# OpenRC
configure_file(openrc/sonic-firewall-service.in openrc/sonic-firewall-service @ONLY)
if(SPLIT_BUILD)
    install(
        PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/openrc/sonic-firewall-service"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/init.d"
        COMPONENT openrc
    )
elseif(OPENRC_FOUND)
    install(
        PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/openrc/sonic-firewall-service"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/init.d"
    )
endif()

# runit
configure_file(runit/run.in runit/run @ONLY)
if(SPLIT_BUILD)
    install(
        PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/runit/run"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/runit/sv/sonic-firewall-service"
        COMPONENT runit
    )
elseif(RUNIT_FOUND)
    install(
        PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/runit/run"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/runit/sv/sonic-firewall-service"
    )
endif()

# s6 (an s6-rc longrun, ordered after dbus)
configure_file(s6/run.in s6/run @ONLY)
if(SPLIT_BUILD)
    install(
        PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/s6/run"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/s6/sv/sonic-firewall-service-srv"
        COMPONENT s6
    )
    install(
        FILES "${CMAKE_CURRENT_SOURCE_DIR}/s6/type"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/s6/sv/sonic-firewall-service-srv"
        COMPONENT s6
    )
    install(
        FILES "${CMAKE_CURRENT_SOURCE_DIR}/s6/dependencies/dbus"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/s6/sv/sonic-firewall-service-srv/dependencies.d"
        COMPONENT s6
    )
elseif(S6_FOUND)
    install(
        PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/s6/run"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/s6/sv/sonic-firewall-service-srv"
    )
    install(
        FILES "${CMAKE_CURRENT_SOURCE_DIR}/s6/type"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/s6/sv/sonic-firewall-service-srv"
    )
    install(
        FILES "${CMAKE_CURRENT_SOURCE_DIR}/s6/dependencies/dbus"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/s6/sv/sonic-firewall-service-srv/dependencies.d"
    )
endif()

# dinit
configure_file(dinit/sonic-firewall-service.in dinit/sonic-firewall-service @ONLY)
if(SPLIT_BUILD)
    install(
        FILES "${CMAKE_CURRENT_BINARY_DIR}/dinit/sonic-firewall-service"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/dinit.d"
        COMPONENT dinit
    )
elseif(DINIT_FOUND)
    install(
        FILES "${CMAKE_CURRENT_BINARY_DIR}/dinit/sonic-firewall-service"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/dinit.d"
    )
endif()

# sysvinit
# OpenRC and sysvinit both install ${CMAKE_INSTALL_SYSCONFDIR}/init.d/sonic-firewall-service.
if(NOT SPLIT_BUILD AND OPENRC_FOUND AND SYSVINIT_FOUND)
    message(FATAL_ERROR "OPENRC_FOUND and SYSVINIT_FOUND both install init.d/sonic-firewall-service; choose one, or use SPLIT_BUILD for separate packages")
endif()
configure_file(sysvinit/sonic-firewall-service.in sysvinit/sonic-firewall-service @ONLY)
if(SPLIT_BUILD)
    install(
        PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/sysvinit/sonic-firewall-service"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/init.d"
        COMPONENT sysvinit
    )
elseif(SYSVINIT_FOUND)
    install(
        PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/sysvinit/sonic-firewall-service"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/init.d"
    )
endif()
