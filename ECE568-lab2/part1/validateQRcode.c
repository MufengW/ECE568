#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define TIME_STEP 30
#define MSG_LENGTH 8
#define CODE_DIGITS 6

#define IPAD 0x36
#define OPAD 0x5c

int DIGITS_POWER[]
// 0 1  2   3    4     5      6       7        8
= {1,10,100,1000,10000,100000,1000000,10000000,100000000 };

void to_hex(char *str, uint8_t *ret);
void xor_mask(uint8_t *key, uint8_t mask);
void gen_msg(int64_t msg_int, uint8_t *msg_hex);
void gen_result(uint8_t *sha, char *result);

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
    SHA1_INFO ctx;
    uint8_t sha[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);

    uint8_t inner[SHA1_BLOCKSIZE];
    memset(inner, 0, SHA1_BLOCKSIZE);
    to_hex(secret_hex, inner);
    xor_mask(inner, IPAD);

    time_t current_time = time(NULL);
    int64_t msg_int = current_time / TIME_STEP;
    uint8_t msg_hex[MSG_LENGTH];
    gen_msg(msg_int, msg_hex);

    sha1_update(&ctx, inner, sizeof(inner));
    sha1_update(&ctx, msg_hex, sizeof(msg_hex));
    sha1_final(&ctx, sha);

    uint8_t outter[SHA1_BLOCKSIZE];
    memset(outter, 0, SHA1_BLOCKSIZE);
    to_hex(secret_hex, outter);
    xor_mask(outter, OPAD);

    sha1_init(&ctx);

    sha1_update(&ctx, outter, sizeof(outter));
    sha1_update(&ctx, sha, sizeof(sha));
    sha1_final(&ctx, sha);

    char result[CODE_DIGITS];
    gen_result(sha, result);

    return(strcmp(TOTP_string, result) == 0);
}

int
main(int argc, char * argv[])
{
    if ( argc != 3 ) {
        printf("Usage: %s [secretHex] [TOTP]\n", argv[0]);
        return(-1);
    }

    char *    secret_hex = argv[1];
    char *    TOTP_value = argv[2];

    assert (strlen(secret_hex) <= 20);
    assert (strlen(TOTP_value) == CODE_DIGITS);

    printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
        secret_hex,
        TOTP_value,
        validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

    return(0);
}

void to_hex(char *str, uint8_t *ret) {
    int idx = 0;
    char tmp[2];
    int len = strlen(str);
    while(len > 0) {
        memcpy(tmp, str, 2);
        ret[idx] = (int)strtol(tmp, NULL, 16);
        str += 2;
        len -= 2;
        idx++;
    }
}

void xor_mask(uint8_t *key, uint8_t mask) {
    for(int i = 0; i < SHA1_BLOCKSIZE; ++i) {
        key[i] ^= mask;
    }
}

void gen_msg(int64_t msg_int, uint8_t *msg_hex) {
    for(int i = 0; i < MSG_LENGTH; ++i) {
        msg_hex[i] = (msg_int >> (8 * (MSG_LENGTH - i - 1))) & 0xff;
    }
}

void gen_result(uint8_t *sha, char *result) {
    int offset = sha[SHA1_DIGEST_LENGTH - 1] & 0xf;
    int binary =
        ((sha[offset] & 0x7f) << 24) |
        ((sha[offset + 1] & 0xff) << 16) |
        ((sha[offset + 2] & 0xff) << 8) |
        (sha[offset + 3] & 0xff);
    int otp = binary % DIGITS_POWER[CODE_DIGITS];
    char *fmt_str;
    sprintf(fmt_str, "%%%dd", CODE_DIGITS);
    sprintf(result, fmt_str, otp);
}
