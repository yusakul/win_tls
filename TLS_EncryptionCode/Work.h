#pragma once
#include "Help.h"

class CWork
{
public:
	CWork(void);
	~CWork(void);
	//��ô����ӿ���Ϊ�˷����C#������һ��
	static __int16 EncryptionCode(char *pPeFileFullInputPath ,char *pPeFileFullOutputPath ,char c32Key);
};


