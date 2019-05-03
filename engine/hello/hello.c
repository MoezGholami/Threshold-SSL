#include <stdio.h>
#include <openssl/engine.h>

#define     true            1
#define     false           0

static const char *engine_id    = "mozengine";
static const char *engine_name  = "a hello world engine for demonstration purposes.";
static int bind(ENGINE *e, const char *id) {
    if (!ENGINE_set_id(e, engine_id)) {
        fprintf(stderr, "ENGINE_set_id failed\n");
        return false;
    }
    if (!ENGINE_set_name(e, engine_name)) {
        printf("ENGINE_set_name failed\n");
        return false;
    }
    return true;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
