#include "stdafx.h"
#include "Help.h"


CHelp::CHelp(void)
{
}


CHelp::~CHelp(void)
{
}

string CHelp::ws2s(const wstring& wide, UINT CodePage){
	int wide_length = static_cast<int>(wide.length());
	if (wide_length == 0)
		return string();

	int charcount = WideCharToMultiByte(CodePage, 0, wide.data(), wide_length,
		NULL, 0, NULL, NULL);
	if (charcount == 0)
		return string();

	string mb;
	mb.resize(charcount);
	WideCharToMultiByte(CodePage, 0, wide.data(), wide_length,
		&mb[0], charcount, NULL, NULL);

	return mb;
}

wstring CHelp::s2ws( const std::string& mb,UINT CodePage){
	if (mb.empty())
		return std::wstring();

	int mb_length = static_cast<int>(mb.length());
	int charcount = MultiByteToWideChar(CodePage, 0,
		mb.data(), mb_length, NULL, 0);
	if (charcount == 0)
		return std::wstring();

	wstring wide;
	wide.resize(charcount);
	MultiByteToWideChar(CodePage, 0, mb.data(), mb_length, &wide[0], charcount);

	return wide;
}

wstring CHelp::GetTempFilePath(){
	WCHAR wcTemp[MAX_PATH] = {};
	GetEnvironmentVariableW(_T("TEMP"), wcTemp, MAX_PATH);
	WCHAR wcTempFilePath[MAX_PATH] = {};
	GetTempFileName(wcTemp, _T("~ed"), 0, wcTempFilePath);
	return wcTempFilePath;
}