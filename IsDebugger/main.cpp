#include <Windows.h>
#include <stdio.h>

void NTAPI __stdcall TLS_CALLBACK(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
	if (IsDebuggerPresent())
	{
		printf("Debugger detected\n");
	}
	else
	{
		printf("No debugger\n");
	}
}

#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")

EXTERN_C

#pragma data_seg (".CRT$XLB")
PIMAGE_TLS_CALLBACK _tls_callback = TLS_CALLBACK;
#pragma data_seg ()

int main()
{
	printf("This is main()\n");
	return 0;
}