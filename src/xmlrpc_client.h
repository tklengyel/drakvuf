#ifndef XMLRPC_CLIENT_H
#define XMLRPC_CLIENT_H

#ifdef HAVE_XMLRPC

void honeybrid_client_init();

void honeybrid_client_finish();

uint32_t honeybrid_add_clone(uint16_t vlan);

void honeybrid_remove_clone(uint32_t backendID);

#else

static inline
void honeybrid_client_init(){};

static inline
void honeybrid_client_finish(){};

static inline
uint32_t honeybrid_add_clone(uint16_t vlan){
    return 0;
};

static inline
void honeybrid_remove_clone(uint32_t backendID){};

#endif /* HAVE_XMLRPC */

#endif
