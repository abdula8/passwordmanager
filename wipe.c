#include <string.h>
#include <windows.h>  // For SecureZeroMemory on Windows

// Cross-platform secure memory wipe
__declspec(dllexport) void secure_wipe(void *ptr, size_t len) {
#ifdef _WIN32
    SecureZeroMemory(ptr, len);
#else
    // POSIX alternative to prevent compiler optimization
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
#endif
}
