cmake_minimum_required(VERSION 3.10)

set(BOREALIS_LIBRARY ${CMAKE_CURRENT_SOURCE_DIR}/../library/borealis/library)

include(${BOREALIS_LIBRARY}/cmake/commonOption.cmake)
include(${BOREALIS_LIBRARY}/cmake/toolchain.cmake)

project(wg_tester)
set(VERSION_MAJOR "1")
set(VERSION_MINOR "0")
set(VERSION_ALTER "0")
set(PROJECT_AUTHOR "switch-wireguard")
set(PROJECT_ICON ${CMAKE_CURRENT_SOURCE_DIR}/resources/icon.jpg)
set(PROJECT_RESOURCES ${CMAKE_CURRENT_SOURCE_DIR}/resources)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../library/borealis/library ${CMAKE_BINARY_DIR}/borealis)

find_package(Threads REQUIRED)
list(APPEND APP_PLATFORM_LIB ${CMAKE_THREAD_LIBS_INIT})

file(GLOB_RECURSE MAIN_SRC src/*.cpp)

if (PLATFORM_SWITCH)
    list(APPEND MAIN_SRC ${BOREALIS_LIBRARY}/lib/platforms/switch/switch_wrapper.c)
endif()

set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../library/lwip)

set(LWIP_SRCS
    ${LWIP_DIR}/src/core/init.c
    ${LWIP_DIR}/src/core/def.c
    ${LWIP_DIR}/src/core/inet_chksum.c
    ${LWIP_DIR}/src/core/ip.c
    ${LWIP_DIR}/src/core/mem.c
    ${LWIP_DIR}/src/core/memp.c
    ${LWIP_DIR}/src/core/netif.c
    ${LWIP_DIR}/src/core/pbuf.c
    ${LWIP_DIR}/src/core/tcp.c
    ${LWIP_DIR}/src/core/tcp_in.c
    ${LWIP_DIR}/src/core/tcp_out.c
    ${LWIP_DIR}/src/core/timeouts.c
    ${LWIP_DIR}/src/core/udp.c
    ${LWIP_DIR}/src/core/ipv4/ip4.c
    ${LWIP_DIR}/src/core/ipv4/ip4_addr.c
    ${LWIP_DIR}/src/core/ipv4/ip4_frag.c
    ${LWIP_DIR}/src/core/ipv4/icmp.c
)

set(LWIP_RELAY_SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/../lwip-relay/src/wg_lwip_relay.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../lwip-relay/src/wg_netif.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../lwip-relay/src/sys_arch.c
)

program_target(${PROJECT_NAME} "${MAIN_SRC}")
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD 17)

target_sources(${PROJECT_NAME} PRIVATE ${LWIP_SRCS} ${LWIP_RELAY_SRCS})

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../library/crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/../lwip-relay/include
    ${LWIP_DIR}/src/include
    ${APP_PLATFORM_INCLUDE}
)

add_library(wireguard STATIC IMPORTED)
set_target_properties(wireguard PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/../libwireguard.a
)

target_compile_options(${PROJECT_NAME} PRIVATE -ffunction-sections -fdata-sections ${APP_PLATFORM_OPTION})
target_link_libraries(${PROJECT_NAME} PRIVATE borealis wireguard ${APP_PLATFORM_LIB})

if (PLATFORM_SWITCH)
    add_custom_target(${PROJECT_NAME}.nro DEPENDS ${PROJECT_NAME}
        COMMAND ${NX_NACPTOOL_EXE} --create "${PROJECT_NAME}" "${PROJECT_AUTHOR}" "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_ALTER}" ${PROJECT_NAME}.nacp --titleid=${PROJECT_TITLEID}
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_RESOURCES} ${CMAKE_BINARY_DIR}/resources
        COMMAND ${NX_ELF2NRO_EXE} ${PROJECT_NAME}.elf ${PROJECT_NAME}.nro --icon=${PROJECT_ICON} --nacp=${PROJECT_NAME}.nacp --romfsdir=${CMAKE_BINARY_DIR}/resources
    )
endif()
