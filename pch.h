#ifndef LUANETWORKBINDING_PCH_H
#define LUANETWORKBINDING_PCH_H
#define WIN32_LEAN_AND_MEAN
#define _MFC_OVERRIDES_NEW
#define NOMINMAX
#define _USE_MATH_DEFINES
#include <windows.h>
#include <windowsx.h>

#include <wrl/client.h>

#include <d3dcompiler.h>
#include <d3d11_1.h>
#include <dxgi1_6.h>

#include <intrin.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <vector>
#include <wincodec.h>
#include <WS2tcpip.h>

#include <lua.hpp>
namespace LuaBinding {
    using string_type = std::string;
}
#include <LuaBinding.h>

struct env {
    void exit() {
        ::exit(0);
    }
    bool should_exit = false;
    bool should_restart = false;
    bool should_relaunch = false;
    std::unique_ptr<LuaBinding::State>(*new_state)() = 0;
};
#endif //LUANETWORKBINDING_PCH_H