#pragma once
#include<tchar.h>
#include<string>
#include<windows.h>
using namespace std;

class CHelp
{
public:
	CHelp(void);
	~CHelp(void);
	static string ws2s(const wstring& wide, UINT CodePage = CP_ACP);
    static wstring s2ws( const std::string& mb,UINT CodePage = CP_ACP);
	static wstring GetTempFilePath();
};

