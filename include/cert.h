#pragma once

#include "error.h"
#include "rsa.h"
#include "x509_key_format.h"

/**
 * @brief Generate an RSA key pair
 *
 * @param size The size of the RSA key
 * @param cert_privkey Pointer to store the generated RSA private key
 * @param cert_pubkey Pointer to store the generated RSA public key
 * @return error_t Returns NO_ERROR on successful key pair generation, otherwise returns ERROR_FAILURE
 *
 */
error_t cert_generate_rsa(int size, RsaPrivateKey *cert_privkey, RsaPublicKey *cert_pubkey);

/**
 * @brief Get RSA private key data
 *
 * @param cert_privkey Pointer to the RSA private key
 * @param priv_data Pointer to store the exported private key data
 * @param priv_size Pointer to store the size of the exported private key data
 * @return error_t Returns NO_ERROR on successful export, otherwise returns ERROR_FAILURE
 *
 * The exported private key is in DER format.
 */
error_t cert_get_rsa_priv(RsaPrivateKey *cert_privkey, uint8_t **priv_data, size_t *priv_size);

/**
 * @brief Load the server's CA certificate and private key
 *
 * @param cert Pointer to store the loaded X509 Certificate Information
 * @param cert_priv Pointer to store the loaded RSA private key
 * @return error_t Returns NO_ERROR on successful load, otherwise returns ERROR_FAILURE
 *
 * The CA certificate and private key are loaded from PEM-formatted strings within the settings.
 */
error_t cert_load_ca(X509CertInfo *cert, RsaPrivateKey *cert_priv);

/**
 * @brief Generate a certificate based on MAC address
 *
 * @param mac Pointer to the MAC address used for certificate generation
 * @param dest Directory where the certificate files should be saved
 * @return error_t Returns NO_ERROR on successful certificate generation, otherwise returns ERROR_FAILURE
 *
 * The client certificate is saved in PEM format and the private key is saved in DER format.
 */

error_t cert_generate_mac(const char *mac, const char *dest);

/**
 * @brief Generate a signed certificate
 *
 * @param subject Pointer to the subject string
 * @param serial_number Pointer to the serial number in bytes
 * @param cert_file File path to store the generated certificate
 * @param cert_der Boolean indicating whether to save the certificate in DER format
 * @param priv_file File path to store the private key
 * @return error_t Returns NO_ERROR on successful certificate generation, otherwise returns ERROR_FAILURE
 *
 * The certificate is either saved in DER or PEM format depending on the cert_der flag.
 * The private key is saved in DER format.
 */
error_t cert_generate_signed(const char *subject, const uint8_t *serial_number, int serial_number_size, bool self_sign, bool cert_der_format, const char *cert_file, const char *priv_file);

/**
 * @brief Generate root and server certificates.
 *
 * @return error_t Returns NO_ERROR on successful generation of both certificates; otherwise, returns ERROR_FAILURE.
 *
 * This function generates two certificates: a root certificate with the subject "TeddyCloud CA Root Certificate" and a server certificate with the subject "TeddyCloud Server."
 * The root certificate is self-signed, and the server certificate is not self-signed.
 * Both certificates are stored in the file paths specified in the settings.
 */
error_t cert_generate_default();

#define CERT_RSA_SIZE 2048
