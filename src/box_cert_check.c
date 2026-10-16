#include "box_cert_check.h"

#include "box_cert.h"
#include "debug.h"
#include "os_port.h"
#include "tls_adapter.h"

/* The fingerprint of the client.der uploaded for this box, if it is the certificate of this box. */
static bool uploaded_cert_pin(settings_t *settings, char_t pin[65])
{
    char_t subject[32];
    char_t id[BOX_CERT_ID_SIZE];

    return tls_cert_fingerprint(settings->internal.client.crt, pin, subject, sizeof(subject)) &&
           box_cert_id(subject, id) && osStrcasecmp(id, settings->commonName) == 0;
}

static void pin_box_cert(settings_t *settings, const char_t *pin)
{
    TRACE_INFO("Box %s: certificate pinned, SHA256 %s\r\n", settings->commonName, pin);
    settings_set_string_id("toniebox.certPin", pin, settings->internal.overlayNumber);
    settings_save();
}

/* Only called for boxes TeddyCloud knows or accepts (core.allowNewBox). The uploaded
 * client.der of the box is its real certificate; without one, the first certificate
 * the box presents is pinned, also a trusted one, so no other certificate takes its place. */
static const char *box_cert_status(const TlsContext *tls, settings_t *settings)
{
    char_t uploaded[65];

    if (uploaded_cert_pin(settings, uploaded))
    {
        if (osStrcasecmp(uploaded, settings->toniebox.certPin) != 0)
        {
            pin_box_cert(settings, uploaded);
        }
    }
    else if (osStrlen(settings->toniebox.certPin) == 0)
    {
        pin_box_cert(settings, tls->client_cert_sha256);
    }
    if (tls->client_cert_trusted)
    {
        return "trusted";
    }
    return osStrcasecmp(settings->toniebox.certPin, tls->client_cert_sha256) == 0 ? "pinned" : "mismatch";
}

bool box_cert_accepted(const TlsContext *tls, settings_t *settings)
{
    const char *status = box_cert_status(tls, settings);
    bool verified = osStrcmp(status, "trusted") == 0 || osStrcmp(status, "pinned") == 0;

    if (osStrcmp(settings->internal.boxCertStatus, status) != 0)
    {
        if (!verified)
        {
            TRACE_WARNING("Box %s: certificate %s, SHA256 %s\r\n", settings->commonName, status, tls->client_cert_sha256);
        }
        settings_set_string_id("internal.boxCertStatus", status, settings->internal.overlayNumber);
    }
    if (osStrcmp(settings->internal.boxCertSha256, tls->client_cert_sha256) != 0)
    {
        settings_set_string_id("internal.boxCertSha256", tls->client_cert_sha256, settings->internal.overlayNumber);
    }
    return verified || !settings->core.boxCertAuth;
}
