#include "toniebox_state.h"
#include "settings.h"

static toniebox_state_t Box_State_Overlay[MAX_OVERLAYS];

void toniebox_state_init()
{
    for (size_t i = 0; i < MAX_OVERLAYS; i++)
    {
        osMemset(&Box_State_Overlay[i], 0, sizeof(toniebox_state_t));
    }
}

toniebox_state_t *get_toniebox_state()
{
    return get_toniebox_state_id(0);
}
toniebox_state_t *get_toniebox_state_id(uint8_t id)
{
    return &Box_State_Overlay[id];
}