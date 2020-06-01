#include "stdafx.h"
#include "InterFace.h"

__int16 EncryptionCode(char *pPeFileFullInputPath ,char *pPeFileFullOutputPath ,char c32Key){
	//MessageBoxA(NULL ,pPeFileFullInputPath ,pPeFileFullOutputPath ,MB_OK);
	return CWork::EncryptionCode(pPeFileFullInputPath ,pPeFileFullOutputPath ,c32Key);
}
