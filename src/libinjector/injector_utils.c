#include "injector_utils.h"

// a dummy stub which should be compatible with the extended definitions of win_injector as well as linux_injector
// since c doesn't support inheritance, this is how it is being done for now ¯\_(ツ)_/¯
// NOTE: sync the variables with linux and windows injector if this stub is updated
struct injector
{
    injector_step_t step;
    bool step_override;
};

event_response_t override_step(injector_t injector, const injector_step_t step, event_response_t event)
{
    injector->step_override = true;
    injector->step = step;
    return event;
}
