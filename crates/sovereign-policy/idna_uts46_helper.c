#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unicode/uidna.h>
#include <unicode/utypes.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 64;
    }

    UErrorCode status = U_ZERO_ERROR;
    const uint32_t options = UIDNA_USE_STD3_RULES | UIDNA_CHECK_BIDI |
                             UIDNA_CHECK_CONTEXTJ | UIDNA_CHECK_CONTEXTO |
                             UIDNA_NONTRANSITIONAL_TO_ASCII |
                             UIDNA_NONTRANSITIONAL_TO_UNICODE;
    UIDNA *idna = uidna_openUTS46(options, &status);
    if (U_FAILURE(status) || idna == NULL) {
        return 65;
    }

    char output[254];
    UIDNAInfo info = UIDNA_INFO_INITIALIZER;
    const size_t input_length = strlen(argv[1]);
    if (input_length == 0 || input_length > INT32_MAX) {
        uidna_close(idna);
        return 66;
    }
    const int32_t length = uidna_nameToASCII_UTF8(
        idna, argv[1], (int32_t)input_length, output, (int32_t)sizeof(output),
        &info, &status);
    uidna_close(idna);
    if (U_FAILURE(status) || info.errors != 0 || length <= 0 || length > 253) {
        return 67;
    }
    if (fwrite(output, 1, (size_t)length, stdout) != (size_t)length) {
        return 68;
    }
    return 0;
}
