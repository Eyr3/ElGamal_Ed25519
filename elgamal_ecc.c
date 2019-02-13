#include <stdio.h>

#include "sodium.h"
#include "ed25519_ref10.h"
#include "elgamal_ecc.h"

uint32_t randombytes_uniform(const uint32_t upper_bound);

void ge25519_add(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_cached *q);

void ge25519_sub(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_cached *q);

void ge25519_scalarmult(ge25519_p3 *h, const unsigned char *a,
                        const ge25519_p3 *p);

int init_point(point **p)
{
	*p = (point*) malloc(sizeof(point));
	(*p)->x = 0;
	(*p)->y = 0;
}

int crypto_ed25519_keypair(eg_ec_ctx **eec_client)
{
    *eec_client = (eg_ec_ctx*) malloc(sizeof(eg_ec_ctx));
    elliptic_curve *ecc = malloc(sizeof(elliptic_curve));
    (*eec_client)->ec = ecc;

    ecc->a = 2;
    ecc->b = 1; /*y^2 = x^3 + 2*x + 1*/
    ecc->N = 97;

    (*eec_client)->sk = randombytes_uniform(ecc->N);
    init_point(&(ecc->base));
    init_point(&((*eec_client)->pk));

    ecc->base->x = 3;
    ecc->base->y = 2;
    printf("\nN = %d", ecc->N);
    printf("\nx = %d", (*eec_client)->sk);

    uint32_t tmp;
    tmp = (*eec_client)->sk;
    (*eec_client)->pk = ge25519_scalarmult((*eec_client)->ec, tmp, ecc->base);
    printf("\nBase Point P = (%d, %d)", ecc->base->x, ecc->base->y);
    printf("\nPublic key xP = (%d, %d)", ((*eec_client)->pk->x, (*eec_client)->pk->y));
}


int encrypt_ed25519(eg_ec_ctx *eec, point *pm)
{
    (*eec)->ek = randombytes_uniform(ecc->N);
    printf("\nEphemeral key ek = %d\n", eec->ek);

    ciphertext *cipher = malloc(sizeof(ciphertext));
    init_point(&cipher->c1);
    init_point(&cipher->c2);
    uint32_t tmp1, tmp2;
    tmp1 = (*eec)->ek;
    cipher->c1 = ge25519_scalarmult(eec->ec, tmp1, ecc->base);

    tmp2 = (*eec)->ek;
    cipher->c2 = ge25519_scalarmult(eec->ec, tmp2, ecc->pk);
    cipher->c2 = ge25519_add(eec->ec, cipher->2, pm)
    printf("\ncipher c1: (%d, %d)", cipher->c1->x, cipher->c1->y);
    printf("\ncipher c2: (%d, %d)", cipher->c2->x, cipher->c2->y);

    return cipher;
}


int decrypt_ed25519(eg_ec_ctx *eec, point c)
{
    point *d1, *d2;
    init_point(&d1);
    init_point(&d2);
    uint32_t tmp;
    tmp = ecc->pk;
    d1 = ge25519_scalarmult(ecc->ec, tmp, c->c1);
    d2 = ge25519_sub(ecc->ec, c->c2, d1);
    printf("\nD1 = (%d, %d)", d1->x, d1->y);
    printf("\nD2 = (%d, %d)", d2->x, d2->y);
    return d2;
}


int main()
{
    eg_ec_ctx *eec;                 //Alice
    crypto_ed25519_keypair(&eec);   //Init Alice

    /*Encrypt message(Pm), generate c=(c1, c2)*/
    point *m;   //Bob: msg->Pm
    ciphertext *c;
    init_point(&m);
    m->x = 6;
    m->y = 17;

    c = encrypt_ed25519(eec, m);

    /*Decrypt ciphertext: D1 = x * C1
    D2 = C2 - C1 = k*Y + Pm - k*x*P = Pm*/
    point *p;
    init_point(&p);
    p = decrypt_ed25519(eec, c);

    return 0;
}
