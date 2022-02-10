#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

void to_hex(char *str, uint8_t *ret);

int
main(int argc, char * argv[])
{
    if ( argc != 4 ) {
        printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
        return(-1);
    }

    char *    issuer = argv[1];
    char *    accountName = argv[2];
    char *    secret_hex = argv[3];

    assert (strlen(secret_hex) <= 20);

    printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
        issuer, accountName, secret_hex);

    // Create an otpauth:// URI and display a QR code that's compatible
    // with Google Authenticator
    char otpauth[256];
    memset(otpauth, 0, 256);
    const char *issuer_encode = urlEncode(issuer);
    const char *accountName_encode = urlEncode(accountName);
    uint8_t secret_hex_encode[17];
    uint8_t secret_hex_arr[10];
    memset(secret_hex_arr, 0, 10);
    to_hex(secret_hex, secret_hex_arr);
    base32_encode(secret_hex_arr, 10,secret_hex_encode, 17);
    sprintf(otpauth, "otpauth://totp/%s?issuer=%s&secret=%s&period=30",
    accountName_encode, issuer_encode, secret_hex_encode);
    displayQRcode(otpauth);

    return (0);
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
