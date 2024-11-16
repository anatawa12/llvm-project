if (CMAKE_SYSTEM_NAME MATCHES "Linux")
add_subdirectory(ELF)
endif ()

if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
  add_subdirectory(MacOSX)
endif()

if (CMAKE_SYSTEM_NAME MATCHES "Windows")
add_subdirectory(PECOFF)
endif()
if (false)
add_subdirectory(wasm)
endif ()
