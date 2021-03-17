#pragma once

#include <libhook/libhook.hpp>
#include "plugins.h"

/*
 * These 2 templates convert member-function-pointer to class type.
 * It is required to properly call member-function-pointer.
 * Read more in <libhook/libhook.hpp>.
 */
template <typename T>
struct class_type;

template <typename T, typename R, typename... Args>
struct class_type<R (T::*)(Args...)>
{
    using type = T;
};

/**
 * This class is only needed for better backwards compatibility.
 * The new hooking interface prefers to use member-functions as callbacks
 * which provides `this`.
 */
class PluginResult : public libhook::CallResult
{
public:
    PluginResult()
        : libhook::CallResult()
    {};

    class pluginex* plugin_ = nullptr;
};

template<typename Plugin>
Plugin* GetTrapPlugin(const drakvuf_trap_info_t* info)
{
    static_assert(std::is_base_of_v<pluginex, Plugin>, "Plugin must derive from pluginex");
    return dynamic_cast<Plugin*>(libhook::GetTrapParams<PluginResult>(info)->plugin_);
}