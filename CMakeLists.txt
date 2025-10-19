cmake_minimum_required(VERSION 3.26)
project(LuaNetworkBinding)

set(CMAKE_CXX_STANDARD 23)

include_directories(.)
include_directories(C:\\LuaJIT-2.1.M.64\\src)
include_directories(..\\..\\shared\\include\\)

file(GLOB_RECURSE misc misc/*.cpp misc/*.h)
file(GLOB_RECURSE socket socket/*.cpp socket/*.h)
file(GLOB_RECURSE websocketpp websocketpp/*.cpp websocketpp/*.h)

add_library(LuaNetworkBinding SHARED main.cpp dll.def ${misc} ${socket} ${websocketpp} pch.h
        connection.cpp
        connection.h)

find_library(LUAJ lua51dyn lib C:\\LuaJIT-2.1.M.64\\src\\)

target_link_libraries(LuaNetworkBinding LINK_PUBLIC ${LUAJ})

MESSAGE(STATUS "LUAJIT: " ${LUAJ})

set_property(TARGET LuaNetworkBinding PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
add_compile_options(
        $<$<CONFIG:>:/MT> #---------|
        $<$<CONFIG:Debug>:/MTd> #---|-- Statically link the runtime libraries
        $<$<CONFIG:Release>:/MT> #--|
)

target_compile_options(LuaNetworkBinding PRIVATE "/Zi" PRIVATE "/O2" PRIVATE "/showIncludes")
target_link_options(LuaNetworkBinding PRIVATE "/nologo" PRIVATE "/OPT:REF" PRIVATE "/OPT:ICF" PRIVATE "/INCREMENTAL" PRIVATE "/MACHINE:X64" PRIVATE "/LARGEADDRESSAWARE" PRIVATE "/LTCG")
target_link_options(LuaNetworkBinding PRIVATE "/DEBUG")
target_link_options(LuaNetworkBinding PRIVATE "/OPT:REF")
target_link_options(LuaNetworkBinding PRIVATE "/OPT:ICF")

add_custom_command(TARGET LuaNetworkBinding POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy LuaNetworkBinding.dll "network.dll")
add_custom_command(TARGET LuaNetworkBinding POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy LuaNetworkBinding.dll "C:\\Users\\Denni\\Desktop\\asklepios\\modules\\network\\network.dll")