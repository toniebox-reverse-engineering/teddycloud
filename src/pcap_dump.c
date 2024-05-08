/* based on https://github.com/luongnv89/pcap-dump */

#include "pcap_dump.h"
#include "fs_port.h"

int pd_write_header(FsFile *fd, int linktype, int thiszone, int snaplen)
{
    struct pd_pcap_file_header hdr;

    hdr.magic = 0xa1b2c3d4;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.thiszone = thiszone;
    hdr.snaplen = snaplen;
    hdr.sigfigs = 0;
    hdr.linktype = linktype;

    fsWriteFile(fd, (char *)&hdr, sizeof(hdr));

    return 0;
}

int pd_write(FsFile *fd, uint8_t *buf, int len, struct timeval tv)
{
    struct pd_pcap_pkthdr h;

    if (len > 65535)
    {
        len = 65535;
    }

    h.ts.tv_sec = (uint32_t)tv.tv_sec;
    h.ts.tv_usec = (uint32_t)tv.tv_usec;

    h.caplen = len;
    h.len = len;

    fsWriteFile(fd, (char *)&h, sizeof(h));
    fsWriteFile(fd, buf, len);
    return 0;
}

FsFile *pd_create(const char *path, int linktype, int thiszone, int snaplen)
{
    FsFile *fd = fsOpenFile(path, FS_FILE_MODE_WRITE);
    if (!fd)
        return NULL;

    pd_write_header(fd, linktype, thiszone, snaplen);

    return fd;
}

void pd_close(FsFile *fd)
{
    fsCloseFile(fd);
}