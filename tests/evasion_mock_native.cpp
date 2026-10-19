#include <windows.h>
#include <stdio.h>

int main() {
    if (IsDebuggerPresent()) {
        printf("Debugger detected!\n");
    }
    OutputDebugStringA("VMWare tools detected");
    printf("Mock Native Binary executed.\n");
    return 0;
}
