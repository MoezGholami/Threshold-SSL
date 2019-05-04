#include <openssl/engine.h>
#include <stdio.h>
#include "constants.h"

int main(int argc, char *argv[]);

int main(int argc, char *argv[]) {
    ENGINE_load_dynamic();
	ENGINE *e = ENGINE_by_id("./hello_engine.so");
    if( e == NULL ) {
        fprintf(stderr, "could not find the engine\n");
        return 1;
    }
    printf("the engine is found, its name is :%s\n", ENGINE_get_name(e));
    return 0;
}
