#pragma once

#include "call_result.hpp"
#include "hooks/base.hpp"
#include "hooks/manual.hpp"
#include "hooks/return.hpp"
#include "hooks/syscall.hpp"

/**
 * A brief information about caveats of libhook.
 *
 * There are 2 things libhook provides:
 *  - RAII containers around libdrakvuf traps
 *  - Trap API unification
 *  - ability to use non-static class-member-functions as callbacks
 *
 * The first two are quite simple, but the third one has some problems:
 *
 * 1) We need to call
 *
 *    event_response_t (Dummy::*)(drakvuf_t, drakvuf_trap_info*)
 *
 * but our `this` reference has signature of `BetterPlugin*`. Problem is solved
 * by clever use of `subject_type` SFINAE (shoutout to @dekrain and @KrzaQ for helping).
 * It obtains class type (in this case `Dummy`) from member-function-pointer and casts `this`
 * to it. Then we just need a standard `std::invoke`.
 *
 * 2) Since we capture `this` in a lambda, we can at most store it in `std::function`
 * while libdrakvuf traps only contain plain C function pointer.
 *
 * That's why hooks in libhook contain callbacks as `std::function`, while using non-capture
 * lambda as trap's callback.
 *
 * The lambda has to:
 *  - get hook from traop
 *  - call callback stored in hook
 */