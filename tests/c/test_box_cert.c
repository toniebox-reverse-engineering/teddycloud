#include <assert.h>
#include <string.h>

#include "box_cert.h"
#include "tests.h"

void test_box_cert_id(void)
{
    char id[BOX_CERT_ID_SIZE];

    assert(box_cert_id("b'aabbccddeeff'", id) && !strcmp(id, "aabbccddeeff"));
    assert(box_cert_id("AABBCCDDEEFF", id) && !strcmp(id, "AABBCCDDEEFF"));
    assert(!box_cert_id("b'aabbccddeeff", id));
    assert(!box_cert_id("TeddyCloud Server", id));
    assert(!box_cert_id("", id));
}

void test_box_cert_issuer_known(void)
{
    assert(box_cert_issuer_known("Boxine Factory SubCA 13", "b'aabbccddeeff'"));
    assert(box_cert_issuer_known("TeddyCloud Root CA", "AABBCCDDEEFF"));
    assert(box_cert_issuer_known("", "TeddyCloud"));
    assert(!box_cert_issuer_known("Some CA", "b'aabbccddeeff'"));
}
