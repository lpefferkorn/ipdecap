cmake_minimum_required(VERSION 2.6)

include(GNUInstallDirs)

project(ipdecap)
set(VERSION 0.5)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/modules/")

option(DEBUG "Debug version" OFF)
IF(DEBUG)
    add_definitions(-DDEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb")
ENDIF(DEBUG)

file(
    GLOB_RECURSE
    source_files
    src/*
)

add_executable(
    ipdecap
    ${source_files}
)

find_package(OpenSSL REQUIRED)
if (OPENSSL_FOUND)
  include_directories(${OPENSSL_INCLUDE_DIRS})
  target_link_libraries (ipdecap ${OPENSSL_LIBRARIES})
else()
  message(FATAL_ERROR "Could not find OpenSSL")
endif()


find_package(Pcap REQUIRED)
if (PCAP_FOUND)
  include_directories(${PCAP_INCLUDE_PATH})
  target_link_libraries (ipdecap ${PCAP_LIBRARY_PATH})
else()
  message(FATAL_ERROR "Could not find Pcap")
endif ()

install(TARGETS ipdecap DESTINATION bin)
install(FILES ipdecap.1
  DESTINATION ${CMAKE_INSTALL_FULL_MANDIR}/man1 COMPONENT doc)
