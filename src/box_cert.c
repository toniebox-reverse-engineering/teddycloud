#include "box_cert.h"

#include <string.h>

static bool contains(const char *text, const char *part)
{
    return strstr(text, part) != NULL;
}

bool box_cert_issuer_known(const char *issuer, const char *subject)
{
    return contains(issuer, "Boxine Factory SubCA") || contains(issuer, "Toniebox SubCA") ||
           contains(issuer, "Toniebox Root CA") || contains(issuer, "TeddyCloud") || contains(subject, "TeddyCloud");
}

bool box_cert_id(const char *subject, char id[BOX_CERT_ID_SIZE])
{
    size_t length = strlen(subject);
    bool quoted = length == 15 && !strncmp(subject, "b'", 2) && subject[14] == '\'';

    if (!quoted && length != 12)
    {
        return false;
    }
    memcpy(id, quoted ? &subject[2] : subject, 12);
    id[12] = '\0';
    return true;
}
