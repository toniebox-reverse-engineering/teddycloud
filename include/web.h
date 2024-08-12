
#include "error.h"

/**
 * @brief Download a file from the specified URL to a local file.
 *
 * This function downloads a file from a given URL and saves it to a specified local file.
 * It handles both HTTP and HTTPS protocols based on the URL scheme and uses secure connections
 * when required.
 *
 * @param[in] url      The URL of the file to download. The URL should be a valid HTTP or HTTPS URL.
 * @param[in] filename The path to the local file where the downloaded content will be saved.
 *
 * @return NO_ERROR if the download was successful, or an appropriate error code otherwise.
 */
error_t web_download(const char *url, const char *filename);
