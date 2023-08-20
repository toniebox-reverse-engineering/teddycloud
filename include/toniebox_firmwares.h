#pragma once

typedef struct
{
    uint32_t timestamp;
    char *version;
    char *branch;
    char *gitShortHash;
    char *hash;

} toniebox_firmware_t;

toniebox_firmware_t *toniebox_firmwares[] = {
    {
        .timestamp = 1620325289,
        .version = "EU_V3.1.0_BF2-0",
        .branch = "3.1.0_BF2_EU",
        .gitShortHash = "2640c1f",
        .hash = "36ef76a6937a128d3bf125d7f08c0c120387e44f7b0d346203a7171f828dafbe",
    },
    {
        .timestamp = 0x0,
        .version = "",
        .branch = "",
        .gitShortHash = "",
        .hash = "",
    },
    {
        .timestamp = 0x0,
        .version = "",
        .branch = "",
        .gitShortHash = "",
        .hash = "",
    }}