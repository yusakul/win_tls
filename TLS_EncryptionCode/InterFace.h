#pragma once
#include "Work.h"

#ifdef TLS_ENCRYPTIONCODE_EXPORTS
#define EXPORTS_CLEAR _declspec(dllexport)
#else
#define EXPORTS_CLEAR _declspec(dllimport)
#endif

//0 �ɹ�
//1 �Ѿ������
//2 ����ʧ��
extern "C" EXPORTS_CLEAR __int16 EncryptionCode(char *pPeFileFullInputPath ,char *pPeFileFullOutputPath ,char c32Key);