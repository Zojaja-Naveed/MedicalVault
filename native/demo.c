/* Command-line test driver for the parser.
 * Usage:  ./demo 'MVLAB|Ali Khan|LABSIGNED'
 */
#include <stdio.h>

int parse_header(const char *input, char *out, size_t out_len);

int main(int argc, char **argv)
{
    char name[64];
    if (argc < 2) {
        printf("usage: %s 'MVLAB|name|signature'\n", argv[0]);
        return 1;
    }
    int r = parse_header(argv[1], name, sizeof name);
    printf("result=%d (1=verified, 0=not verified, negative=rejected) patient=%s\n",
           r, r >= 0 ? name : "-");
    return 0;
}
