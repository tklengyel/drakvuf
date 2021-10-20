#ifndef INJECTOR_UTILS_H
#define INJECTOR_UTILS_H
#include "libinjector.h"
#include <libdrakvuf/libdrakvuf.h>
#include <libinjector/private.h>

event_response_t override_step(injector_t injector, const injector_step_t step, event_response_t event);
#endif
