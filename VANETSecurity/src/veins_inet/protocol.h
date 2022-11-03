#include<pbc.h>
#include<pbc_test.h>

void sysInit(){
    pairing_t pairing;
    element_t P;
    element_t g, h;
    element_t public_key, sig;
    element_t secret_key;
    element_t temp1, temp2;

    pbc_demo_pairing_init(pairing, argc, argv);

    element_init_G1(P, pairing);
    element_init_G1(h, pairing);
    element_init_Zr(secret_key, pairing);
    //4 collision hash functions SHA1
    element_init_G2(temp1, pairing);
    element_init_G2(temp2, pairing);

    element_clear(sig);
    element_clear(public_key);
    element_clear(secret_key);
    element_clear(g);
    element_clear(h);
    element_clear(temp1);
    element_clear(temp2);
    pairing_clear(pairing);
    return 0;
}

void keyGen(){

}
