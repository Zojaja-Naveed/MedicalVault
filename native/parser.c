/*
 * MedVault native report-header parser (libparser.so)
 *
 * Header format (first line of every .lab file):
 *     MVLAB|<patient name>|<signature>
 * A report is "verified" only when the signature is LABSIGNED.
 *
 * FIXED (T-01, CWE-120): the length is checked before every copy, and
 * the library is compiled with -fstack-protector-strong -D_FORTIFY_SOURCE=2.
 */
#include <stdio.h>
#include <string.h>

#define MAX_INPUT 4096

typedef struct {
    char patient[32];
    int  verified;
} ReportHeader;

int parse_header(const char *input, char *out, size_t out_len)
{
    ReportHeader h;
    memset(&h, 0, sizeof h);

    if (input == NULL || out == NULL || out_len == 0) return -1;
    if (strnlen(input, MAX_INPUT) >= MAX_INPUT) return -2;      /* too long */

    const char *p = strchr(input, '|');
    if (!p) return -1;
    p++;
    const char *end = strchr(p, '|');
    size_t n = end ? (size_t)(end - p) : strlen(p);

    if (n == 0 || n >= sizeof h.patient) return -2;    /* FIX: reject oversize name */

    memcpy(h.patient, p, n);                            /* safe: n < 32 */
    h.patient[n] = '\0';
    h.verified = (end && strncmp(end + 1, "LABSIGNED", 9) == 0) ? 1 : 0;

    snprintf(out, out_len, "%s", h.patient);            /* bounded copy out */
    return h.verified;
}
