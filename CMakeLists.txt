cmake_minimum_required(VERSION 3.26)
project(LuaNetworkBinding)

set(CMAKE_CXX_STANDARD 23)

include_directories(.)
include_directories(Dependencies\\Include\\)
include_directories(C:\\LuaJIT-2.1.M.64\\src)
include_directories(D:\\LuaBindingGit\\)

add_library(LuaNetworkBinding SHARED main.cpp dll.def)

find_library(LUAJ5164_3 lua51 lib C:\\LuaJIT-2.1.M.64\\src\\)

target_link_libraries(LuaNetworkBinding LINK_PUBLIC ${LUAJ5164_3})

MESSAGE(STATUS "LUAJIT: " ${LUAJ5164_3})

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
