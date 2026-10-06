#include <stdio.h>
#include <string.h>

#include "Crypto_SHA256.h"
#include "Crypto_ECDSA.h"

static void print_hex(const uint8 *data, uint32 length)
{
    for (uint32 i = 0u; i < length; i++)
    {
        printf("%02x", data[i]);
    }

    printf("\n");
}

static int calculate_sha256(
    const char *message,
    uint8 *digest,
    uint32 *digestLength)
{
    Std_ReturnType result;

    result = Crypto_SHA256_Calculate(
        (const uint8 *)message,
        (uint32)strlen(message),
        digest,
        digestLength);

    if (result != E_OK)
    {
        printf("SHA-256 FAILED! Error = 0x%02x\n", result);
        return 0;
    }

    return 1;
}

int main(void)
{
    /* ============================================================
     * 1. TEST MESSAGE
     * ============================================================ */
    const char *message = "Hello ECDSA!";

    uint8 digest[CRYPTO_SHA256_DIGEST_SIZE];
    uint32 digestLength = sizeof(digest);

    /* ============================================================
     * 2. ECDSA KEY PAIR
     * ============================================================ */
    Crypto_ECDSA_KeyPairType keyPair;

    /* ============================================================
     * 3. SIGNATURE
     * ============================================================ */
    uint8 signature[CRYPTO_ECDSA_P256_SIG_SIZE];
    uint32 signatureLength = sizeof(signature);

    /* ============================================================
     * 4. VERIFY RESULT
     * ============================================================ */
    Crypto_VerifyResultType verifyResult;

    printf("========================================\n");
    printf("       ECDSA P-256 TEST PROGRAM\n");
    printf("========================================\n\n");

    /*
     * ------------------------------------------------------------
     * STEP 1: Generate ECDSA key pair
     * ------------------------------------------------------------
     */
    printf("[1] Generating ECDSA key pair...\n");

    if (Crypto_ECDSA_GenerateKeyPair(&keyPair) != E_OK)
    {
        printf("ERROR: Key generation failed!\n");
        return 1;
    }

    printf("Key generation: SUCCESS\n\n");

    /*
     * ------------------------------------------------------------
     * STEP 2: Print public key
     * ------------------------------------------------------------
     */
    printf("Private Key:\n");
    print_hex(keyPair.privateKey, CRYPTO_ECDSA_P256_KEY_SIZE);

    printf("\nPublic Key X:\n");
    print_hex(keyPair.publicKeyX, CRYPTO_ECDSA_P256_KEY_SIZE);

    printf("\nPublic Key Y:\n");
    print_hex(keyPair.publicKeyY, CRYPTO_ECDSA_P256_KEY_SIZE);

    /*
     * ------------------------------------------------------------
     * STEP 3: Set private key vào SIGN slot
     * ------------------------------------------------------------
     */
    printf("\n[2] Setting private key...\n");

    if (Crypto_ECDSA_SetPrivateKey(
            KEY_SLOT_SIGN,
            keyPair.privateKey,
            CRYPTO_ECDSA_P256_KEY_SIZE) != E_OK)
    {
        printf("ERROR: Set private key failed!\n");
        return 1;
    }

    printf("Private key: SUCCESS\n");

    /*
     * ------------------------------------------------------------
     * STEP 4: Set public key vào VERIFY slot
     * ------------------------------------------------------------
     */
    printf("\n[3] Setting public key...\n");

    if (Crypto_ECDSA_SetPublicKey(
            KEY_SLOT_VERIFY,
            keyPair.publicKeyX,
            keyPair.publicKeyY,
            CRYPTO_ECDSA_P256_KEY_SIZE) != E_OK)
    {
        printf("ERROR: Set public key failed!\n");
        return 1;
    }

    printf("Public key: SUCCESS\n");

    /*
     * ------------------------------------------------------------
     * STEP 5: SHA-256(message)
     * ------------------------------------------------------------
     */
    printf("\n[4] Calculating SHA-256...\n");

    printf("Message: \"%s\"\n", message);

    if (!calculate_sha256(message, digest, &digestLength))
    {
        return 1;
    }

    printf("Digest: ");
    print_hex(digest, digestLength);

    /*
     * ------------------------------------------------------------
     * STEP 6: ECDSA SIGN
     * ------------------------------------------------------------
     */
    printf("\n[5] Signing digest...\n");

    if (Crypto_ECDSA_Sign(
            KEY_SLOT_SIGN,
            digest,
            digestLength,
            signature,
            &signatureLength) != E_OK)
    {
        printf("ERROR: ECDSA signing failed!\n");
        return 1;
    }

    printf("Signature length: %lu bytes\n",
           (unsigned long)signatureLength);

    printf("Signature R:\n");
    print_hex(signature, 32u);

    printf("Signature S:\n");
    print_hex(signature + 32u, 32u);

    /*
     * ------------------------------------------------------------
     * STEP 7: ECDSA VERIFY
     * ------------------------------------------------------------
     */
    printf("\n[6] Verifying signature...\n");

    if (Crypto_ECDSA_Verify(
            KEY_SLOT_VERIFY,
            digest,
            digestLength,
            signature,
            signatureLength,
            &verifyResult) != E_OK)
    {
        printf("ERROR: ECDSA verify operation failed!\n");
        return 1;
    }

    if (verifyResult == CRYPTO_E_VER_OK)
    {
        printf("VERIFY: VALID\n");
    }
    else
    {
        printf("VERIFY: INVALID\n");
        return 1;
    }

    /*
     * ------------------------------------------------------------
     * STEP 8: TEST TAMPERING
     *
     * Thay đổi message -> digest thay đổi
     * Signature cũ không còn hợp lệ
     * ------------------------------------------------------------
     */
    printf("\n========================================\n");
    printf("        TAMPERING TEST\n");
    printf("========================================\n");

    const char *tamperedMessage = "Hello ECDSA?";

    uint8 tamperedDigest[CRYPTO_SHA256_DIGEST_SIZE];
    uint32 tamperedDigestLength = sizeof(tamperedDigest);

    printf("Original message : \"%s\"\n", message);
    printf("Tampered message : \"%s\"\n", tamperedMessage);

    if (!calculate_sha256(
            tamperedMessage,
            tamperedDigest,
            &tamperedDigestLength))
    {
        return 1;
    }

    printf("\nTampered digest: ");
    print_hex(tamperedDigest, tamperedDigestLength);

    /*
     * Verify bằng:
     *   tampered digest
     *   +
     *   signature cũ
     *
     * Phải FAIL.
     */
    if (Crypto_ECDSA_Verify(
            KEY_SLOT_VERIFY,
            tamperedDigest,
            tamperedDigestLength,
            signature,
            signatureLength,
            &verifyResult) != E_OK)
    {
        printf("Verify operation returned ERROR\n");
        return 1;
    }

    if (verifyResult == CRYPTO_E_VER_OK)
    {
        printf("TAMPERING TEST: ERROR - signature still VALID!\n");
        return 1;
    }
    else
    {
        printf("TAMPERING TEST: PASS - signature INVALID\n");
    }

    printf("\n========================================\n");
    printf("           ALL TESTS PASSED\n");
    printf("========================================\n");

    return 0;
}