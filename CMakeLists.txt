cmake_minimum_required(VERSION 2.6)

project(snaptrace)
set(CMAKE_BUILD_TYPE Release)

find_package(PNG REQUIRED)
include_directories(${PNG_INCLUDE_DIR})
link_libraries(${PNG_LIBRARY})

find_library(SPECTRUM_LIBRARY NAMES spectrum ENV LD_LIBRARY_PATH)
find_path(SPECTRUM_INCLUDE_DIR libspectrum.h)
if (SPECTRUM_LIBRARY AND SPECTRUM_INCLUDE_DIR)
  MESSAGE(STATUS "Found libspectrum: ${SPECTRUM_LIBRARY}")
  include_directories(${SPECTRUM_INCLUDE_DIR})
  link_libraries(${SPECTRUM_LIBRARY})
else ()
  MESSAGE(FATAL_ERROR "libspectrum not found!")
endif ()

set(ROM_DIR "${CMAKE_INSTALL_PREFIX}/share/${PROJECT_NAME}/")

configure_file("${PROJECT_SOURCE_DIR}/48.rom" ${CMAKE_CURRENT_BINARY_DIR}/ COPYONLY)
configure_file("${PROJECT_SOURCE_DIR}/config.h.in" "${PROJECT_SOURCE_DIR}/config.h")
add_definitions(-DHAVE_CONFIG_H)

add_executable(${CMAKE_PROJECT_NAME} ${CMAKE_PROJECT_NAME}.cpp)
set_property(TARGET ${CMAKE_PROJECT_NAME} PROPERTY INSTALL_RPATH_USE_LINK_PATH TRUE)

install(TARGETS ${CMAKE_PROJECT_NAME} DESTINATION bin)
install(FILES "${PROJECT_SOURCE_DIR}/48.rom" DESTINATION ${ROM_DIR})
