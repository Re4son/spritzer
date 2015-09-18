/****************************************************************************
*    spritzer -- Cross platform Spritz Crypter
*
*                Program to encrypt payload with, or
*                to decrypt and execute payload
*                depending on the command line arguments
*                We are using the experimental SPRITZ cypher
*
*    Version   : 1.0
*    Release   : 16/06/2015
*    Author    : Re4son <re4son [ at ] whitedome.com.au>
*    Doc       : http://www.whitedome.com.au/spritzer
*    Purpose   : to encrypt / decrypt&execute a shellcode
*    Platforms : Windows and Linux - both 32 and 64 bit
*
*    Compile   : Linux   = gcc -z execstack spritzer.c -o spritzer
*                Windows = gcc spritzer.c -o spritzer.exe
*		            (compile in VM with NX turned off)
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
*                spits out a warning when found. NULL characters stuff up
*                strlen so you better change the password or hard code the
*                lenght in main().
*
****************************************************************************/
