#define PATH_SEPARATOR_WINDOWS '\\'
#define PATH_SEPARATOR_LINUX '/'
#ifdef _WIN32
#define PATH_SEPARATOR PATH_SEPARATOR_WINDOWS
#else
#define PATH_SEPARATOR PATH_SEPARATOR_LINUX
#endif

// Raise the maximum filename length from the cyclone default of 127 so long
// library/tonie filenames resolve (issue #374). cyclone/common/fs_port.h includes
// this config header before its own `#ifndef FS_MAX_NAME_LEN` guard, so defining
// it here cleanly overrides the default without patching the vendored header.
#define FS_MAX_NAME_LEN 255