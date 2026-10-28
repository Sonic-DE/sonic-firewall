# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

include(GenerateExportHeader)

# Init-system operations and the daemon protocol, shared by the KCM, the root daemon and both KAuth helpers.
add_library(kcm_firewall_initsystem STATIC initsystem.cpp initsystem.h serviceprotocol.cpp serviceprotocol.h)
set_target_properties(kcm_firewall_initsystem PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(kcm_firewall_initsystem PUBLIC Qt::Core KF6::I18n Sonic::InitInfo Sonic::Logging)
target_include_directories(kcm_firewall_initsystem PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>")

set(core_files
    appprofiles.cpp
    appprofiles.h
    firewallclient.cpp
    firewallclient.h
    ifirewallclientbackend.cpp
    ifirewallclientbackend.h
    ipvalidator.cpp
    ipvalidator.h
    loglistmodel.cpp
    loglistmodel.h
    profile.cpp
    profile.h
    rule.cpp
    rule.h
    rulelistmodel.cpp
    rulelistmodel.h
    servicejob.cpp
    servicejob.h
    sonicloggingcomponent.cpp
    types.cpp
    types.h
)

set(core_link_libraries
    Qt::Quick
    KF6::CoreAddons
    KF6::ConfigCore
    KF6::I18n
    KF6::AuthCore
    Sonic::Ipc
    Sonic::Logging
    kcm_firewall_initsystem
)

add_library(kcm_firewall_core ${core_files})
target_link_libraries(kcm_firewall_core ${core_link_libraries})

generate_export_header(kcm_firewall_core)

target_include_directories(kcm_firewall_core PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>")

install(TARGETS kcm_firewall_core ${KDE_INSTALL_TARGETS_DEFAULT_ARGS})

add_subdirectory(helper)
add_subdirectory(daemon)
