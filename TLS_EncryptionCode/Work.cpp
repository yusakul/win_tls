#include "stdafx.h"
#include "Work.h"
#include  <stdlib.h>      
#include  <time.h>

#define RETURN_SUCCESSFUL 0  //成功
#define RETURN_ALREADY    1  //已经处理过
#define RETURN_ERROR      2  //失败

#define RESERVEDLENGTH_L  0x200  //保护代码段的TLS本身解密代码不被加密的左侧预留长度（最大长度，实际可能是<=0x200）
#define RESERVEDLENGTH_R  0x1000  //同上的右侧预留长度
#define MARKDOKEY         0x7    //用于标记是否加密过，这个值是存在PE头的第二个字段（之前默认90的位置<DWORD>），只要是7的倍数就认为处理过，防止杀软定位特征码，同时这个也可以是别的倍数，最好是素数。

DWORD m_dwMarkKey[] = {0x13171523 ,0x33171519 ,0x16957582};


CWork::CWork(void)
{
}


CWork::~CWork(void)
{
}

__int16 CWork::EncryptionCode(char *pPeFileFullInputPath ,char *pPeFileFullOutputPath ,char c32Key){
	
	wstring wsInPutCacheFile = CHelp::GetTempFilePath();
	DeleteFile(wsInPutCacheFile.c_str());
	if(!CopyFile(CHelp::s2ws(pPeFileFullInputPath).c_str(),wsInPutCacheFile.c_str(),FALSE)){
        DeleteFile(wsInPutCacheFile.c_str());
	    return RETURN_ERROR;
	}
	HANDLE hdCacheFile = CreateFile(wsInPutCacheFile.c_str(),GENERIC_ALL,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if(INVALID_HANDLE_VALUE == hdCacheFile){
		DeleteFile(wsInPutCacheFile.c_str());
		return RETURN_ERROR;
	}
	DWORD dwFileSize = GetFileSize(hdCacheFile,NULL);
	char *bCache = new char[dwFileSize];
	DWORD dwReadSize = 0;
	ReadFile(hdCacheFile,bCache,dwFileSize,&dwReadSize,NULL);
	if(bCache[0] != 'M' || bCache[1] != 'Z'){ 
		CloseHandle(hdCacheFile);
		delete bCache;
		DeleteFile(wsInPutCacheFile.c_str());
		return RETURN_ERROR;
	}
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)bCache;
	PIMAGE_NT_HEADERS32 pe = (PIMAGE_NT_HEADERS32)(bCache + dos->e_lfanew);
	IMAGE_FILE_HEADER *fileHeader = (IMAGE_FILE_HEADER*)&(pe->FileHeader);
	DWORD pe_len = fileHeader->SizeOfOptionalHeader; 
	PIMAGE_SECTION_HEADER tempSection = (PIMAGE_SECTION_HEADER)((DWORD)fileHeader + 0x14 + pe_len);

	//char *pPoint = &(bCache[2]);
	char* pPoint = ((char*)pe)-12;
	WORD wdMarkDOKey = *((WORD*)pPoint);
	BOOL bIsAlreadyDo = (wdMarkDOKey != 0 && wdMarkDOKey % 7 == 0);
	if(bIsAlreadyDo){
		CloseHandle(hdCacheFile);
		delete bCache;
		DeleteFile(wsInPutCacheFile.c_str());
	    return RETURN_ALREADY;
	}

	DWORD dwTextStartAddress = (DWORD)bCache + tempSection->PointerToRawData;
	DWORD dwTextEndAddress = (DWORD)bCache + tempSection->PointerToRawData + tempSection->SizeOfRawData;
	DWORD dwKeyAddress = -1;
	for(DWORD i = dwTextStartAddress ;i < dwTextEndAddress  - 12;i ++){
	    if(*(DWORD*)i == m_dwMarkKey[0]){
			if(*(DWORD*)(i + sizeof(DWORD)) == m_dwMarkKey[1]){
				if(*(DWORD*)(i + sizeof(DWORD) * 2) == m_dwMarkKey[2]){
					dwKeyAddress = i;
					break;
				}
			}
	    }
	}
	if(dwKeyAddress == -1){
      CloseHandle(hdCacheFile);
	  delete bCache;
	  DeleteFile(wsInPutCacheFile.c_str());
	  MessageBox(NULL, L"ERROR", L"flag write error", MB_OK);
	  return RETURN_ERROR;
	}

	srand((unsigned)time(0));  
	WORD wdRandKey = (rand() % 20 + 1) * MARKDOKEY;
	//pPoint = &(bCache[2]);
	pPoint = ((char*)pe) - 12;
	*((WORD*)pPoint) = wdRandKey; //0x90
	//pPoint = &(bCache[4]);
	pPoint = ((char*)pe) - 10;
	*((DWORD*)pPoint) = c32Key;  //0x3
	tempSection->Characteristics = 0xE0000020; //修改exe代码段的读写权限
 
	//计算（预估）真正的需要保护的代码段，这部分代码段不能进行加密，因为存的的TLS解密代码
    DWORD dwKeyMemoryAddress_L = dwKeyAddress - RESERVEDLENGTH_L;
	if(dwKeyMemoryAddress_L < dwTextStartAddress){
		dwKeyMemoryAddress_L = dwTextStartAddress;
	}
	DWORD dwKeyMemoryAddress_R = dwKeyAddress + RESERVEDLENGTH_R;
	if(dwKeyMemoryAddress_R > dwTextEndAddress){
		dwKeyMemoryAddress_R = dwTextEndAddress;
	}

	for(DWORD i = dwTextStartAddress;i < dwTextEndAddress;i ++){
	    if(i >= dwKeyMemoryAddress_L && i <= dwKeyMemoryAddress_R){
		    continue;
		}
		char cNowMemory = *(char*)(i);
		if(cNowMemory == 0 || cNowMemory == c32Key){
		    continue;
		}
		/*
		if(cNowMemory == 0xE8 || cNowMemory ^ c32Key == 0xE8){
			continue;
		}*/

		cNowMemory = cNowMemory^c32Key;
		*(char*)(i) = cNowMemory;
	}

	DWORD dwWriteSize = 0;
	SetFilePointer(hdCacheFile,0,0,FILE_BEGIN);
	WriteFile(hdCacheFile,bCache,dwReadSize,&dwWriteSize,NULL); 
	CloseHandle(hdCacheFile);
	delete bCache;

	if(!CopyFile(wsInPutCacheFile.c_str() ,CHelp::s2ws(pPeFileFullOutputPath).c_str() ,FALSE)){
		DeleteFile(wsInPutCacheFile.c_str());
		return RETURN_ERROR;
	}
	DeleteFile(wsInPutCacheFile.c_str());
	MessageBox(NULL, L"SUCCESS", L"SUCCESS!", MB_OK);
    return RETURN_SUCCESSFUL;
}
