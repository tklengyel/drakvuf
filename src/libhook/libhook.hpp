#pragma once

#include "call_result.hpp"
#include "hooks/base.hpp"
#include "hooks/manual.hpp"
#include "hooks/return.hpp"
#include "hooks/syscall.hpp"

/**
 * A brief information about caveats of libhook.
 *
 * There are few things libhook provides:
 *  1) RAII containers around libdrakvuf traps
 *  2) Trap API unification
 *  3) ability to use non-static class-member-functions as callbacks
 *
 * 1) I spent over 2 days debugging this issue, so I'm going to note it down here (for future reference).
 *
 * If we delete a hook, we call dctor of the hook object, where we call drakvuf_remove_trap.
 * The problem is that drakvuf doesn't immediately remove those traps, but waits for entire drakvuf loop
 * to pass. This means that drakvuf might call hook, which has been already free'd.
 *
 * To avoid this we overwrite hook->trap_->cb with nullstub, which is a more "sane" (what user expects to happen).
 *
 *
 * 2) Well. this was quite easy, libhook introduces factory functions for that :)
 *
 *
 * 3a) We need to call
 *
 *    event_response_t (Dummy::*)(drakvuf_t, drakvuf_trap_info*)
 *
 * but our `this` reference has signature of `BetterPlugin*`. Problem is solved
 * by clever use of `subject_type` SFINAE (shoutout to @dekrain and @KrzaQ for helping).
 * It obtains class type (in this case `Dummy`) from member-function-pointer and casts `this`
 * to it. Then we just need a standard `std::invoke`.
 *
 * 3b) Since we capture `this` in a lambda, we can at most store it in `std::function`
 * while libdrakvuf traps only contain plain C function pointer.
 *
 * That's why hooks in libhook contain callbacks as `std::function`, while using non-capture
 * lambda as trap's callback.
 *
 * The lambda has to:
 *  - get hook from traop
 *  - call callback stored in hook
 */