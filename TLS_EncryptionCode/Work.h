#pragma once
#include "Help.h"

class CWork
{
public:
	CWork(void);
	~CWork(void);
	//这么定义接口是为了方便和C#集成在一起
	static __int16 EncryptionCode(char *pPeFileFullInputPath ,char *pPeFileFullOutputPath ,char c32Key);
};


