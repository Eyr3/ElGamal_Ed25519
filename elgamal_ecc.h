#include <stdio.h>

#include "sodium.h"

typedef struct point {
    uint32_t x, y;
} point;

typedef struct elliptic_curve {
    uint32_t a, b, N;
    point *base;
} elliptic_curve;

typedef struct eg_ec_ctx {
    uint32_t sk, ek;     /*sk is Alice's secret key. ek is Bob's ephemeral key.*/
    point *pk;           /*pk is public key*/
    elliptic_curve *ec;
} eg_ec_ctx;

typedef struct ciphertext {
    point *c1, *c2;
} ciphertext;

/*
My understanding:
ge25519_p1p1: elliptic_curve
ge25519_p3: uint32_t
ge25519_cached: point p
---------------------------------

ge25519_p3     p_p3, q_p3, r_p3;
ge25519_p1p1   r_p1p1;

void ge25519_add(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_cached *q);
void ge25519_sub(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_cached *q);
void ge25519_scalarmult(ge25519_p3 *h, const unsigned char *a,
                        const ge25519_p3 *p);
*/
