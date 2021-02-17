#pragma once

#include <libhook/libhook.hpp>
#include "plugins.h"

/**
 * These 2 templates convert member-function-pointer to class type.
 * It is required to properly call member-function-pointer.
 * Read more in <libhook/libhook.hpp>.
 */
template <typename T>
struct subject_type;

template <typename T, typename R, typename... Args>
struct subject_type<R (T::*)(Args...)>
{
    using type = T;
};

/**
 * This class is only needed for better backwards compatibility.
 * It "works" as a GetTrapPlugin from pluginex interface.
 *
 * The new hooking interface prefers to use member-functions as callbacks
 * which provides `this`.
 */
class PluginResult : public libhook::CallResult
{
public:
    PluginResult()
        : libhook::CallResult()
    {};

    class BetterPlugin* plugin_ = nullptr;
};

class BetterPlugin : public plugin
{
public:
    using callback_t = libhook::callback_t;

    BetterPlugin(drakvuf_t drakvuf, output_format_t output)
        : plugin(),
          drakvuf_(drakvuf),
          output_format_(output)
    {};

    #pragma region ManualHook

    [[nodiscard]]
    std::unique_ptr<libhook::manual_hook> createManualHook(drakvuf_trap_t* info, drakvuf_trap_free_t free_routine)
    {
        return libhook::manual_hook::create(this->drakvuf_, info, free_routine);
    }

    #pragma endregion ManualHook

    #pragma region ReturnHook

    template<typename Params = PluginResult>
    [[nodiscard]]
    std::unique_ptr<libhook::return_hook> createReturnHook(drakvuf_trap_info* info, callback_t cb)
    {
        static_assert(std::is_base_of_v<PluginResult, Params>, "Params must derive from PluginResult");
        auto hook = libhook::return_hook::create(this->drakvuf_, info, cb);
        static_cast<Params*>(hook->trap_->data)->plugin_ = this;
        return hook;
    }

    template<typename Params = PluginResult, typename Callback>
    [[nodiscard]]
    std::unique_ptr<libhook::return_hook> createReturnHook(drakvuf_trap_info* info, Callback cb)
    {
        static_assert(std::is_base_of_v<PluginResult, Params>, "Params must derive from PluginResult");
        auto hook = libhook::return_hook::create(this->drakvuf_, info, [=](auto&& ...args) -> event_response_t
        {
            return std::invoke(cb, (typename subject_type<Callback>::type*)this, args...);
        });
        static_cast<Params*>(hook->trap_->data)->plugin_ = this;
        return hook;
    }

    #pragma endregion ReturnHook

    #pragma region SyscallHook

    template<typename Params = PluginResult>
    [[nodiscard]]
    std::unique_ptr<libhook::syscall_hook> createSyscallHook(const std::string& syscall_name, callback_t cb)
    {
        static_assert(std::is_base_of_v<PluginResult, Params>, "Params must derive from PluginResult");
        auto hook = libhook::syscall_hook::create(this->drakvuf_, syscall_name, cb);
        static_cast<Params*>(hook->trap_->data)->plugin_ = this;
        return hook;
    }

    template<typename Params = PluginResult, typename Callback>
    [[nodiscard]]
    std::unique_ptr<libhook::syscall_hook> createSyscallHook(const std::string& syscall_name, Callback cb)
    {
        static_assert(std::is_base_of_v<PluginResult, Params>, "Params must derive from PluginResult");
        auto hook = libhook::syscall_hook::create(this->drakvuf_, syscall_name, [=](auto&& ...args) -> event_response_t
        {
            return std::invoke(cb, (typename subject_type<Callback>::type*)this, args...);
        });
        static_cast<Params*>(hook->trap_->data)->plugin_ = this;
        return hook;
    }

    #pragma endregion SyscallHook

protected:
    drakvuf_t drakvuf_;
    output_format_t output_format_;
};