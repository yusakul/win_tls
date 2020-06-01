// TEST.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <string>
#include <windows.h>

using namespace std;

int main(int argc, char* argv[])
{
	//MessageBox(NULL ,L"mark" ,L"tit" ,MB_OK);
	//return 0;
	typedef __int16 (*ENCRYPTIONCODE)(char *pPeFileFullInputPath ,char *pPeFileFullOutputPath ,char c32Key);
	HMODULE hhandle  = LoadLibrary(L"TLS_EncryptionCode.dll");
	if(hhandle && argv[1]!=NULL){
		ENCRYPTIONCODE  _EncryptionCode  = (ENCRYPTIONCODE) GetProcAddress(hhandle ,"EncryptionCode");
		if(_EncryptionCode){
			__int16 bEncryResult = _EncryptionCode((char*)argv[1],"./TESTTLS.exe" ,11);
		}
		FreeLibrary(hhandle);
	}
	else
	{
		MessageBox(NULL, L"TEST.exe + filepath", L"tip", MB_OK);
	}
	return 0;
}

