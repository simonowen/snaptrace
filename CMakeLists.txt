cmake_minimum_required(VERSION 2.6)

project(snaptrace)

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

add_executable(${CMAKE_PROJECT_NAME} ${CMAKE_PROJECT_NAME}.cpp)
install(TARGETS ${CMAKE_PROJECT_NAME} DESTINATION bin)
