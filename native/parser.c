/*
 * MedVault native report-header parser (libparser.so)
 *
 * Header format (first line of every .lab file):
 *     MVLAB|<patient name>|<signature>
 * A report is "verified" only when the signature is LABSIGNED.
 *
 * WARNING: this version is deliberately vulnerable (T-01, CWE-120).
 * It copies the patient name into a 32-byte buffer without checking
 * the length, so a long name overwrites the "verified" flag next to it.
 */
#include <stdio.h>
#include <string.h>

typedef struct {
    char patient[32];   /* fixed-size buffer                         */
    int  verified;      /* stored right after the buffer in memory   */
} ReportHeader;

int parse_header(const char *input, char *out, size_t out_len)
{
    ReportHeader h;
    const char *p = strchr(input, '|');
    if (!p) return -1;
    p++;
    const char *end = strchr(p, '|');
    size_t n = end ? (size_t)(end - p) : strlen(p);

    /* check the lab signature first */
    h.verified = (end && strncmp(end + 1, "LABSIGNED", 9) == 0) ? 1 : 0;

    memcpy(h.patient, p, n);   /* BUG: n is never compared with 32 */
    h.patient[n] = '\0';

    snprintf(out, out_len, "%s", h.patient);
    return h.verified != 0;
}
