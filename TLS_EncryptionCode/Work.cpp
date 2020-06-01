#include "stdafx.h"
#include "Work.h"
#include  <stdlib.h>      
#include  <time.h>

#define RETURN_SUCCESSFUL 0  //�ɹ�
#define RETURN_ALREADY    1  //�Ѿ������
#define RETURN_ERROR      2  //ʧ��

#define RESERVEDLENGTH_L  0x200  //��������ε�TLS������ܴ��벻�����ܵ����Ԥ�����ȣ���󳤶ȣ�ʵ�ʿ�����<=0x200��
#define RESERVEDLENGTH_R  0x1000  //ͬ�ϵ��Ҳ�Ԥ������
#define MARKDOKEY         0x7    //���ڱ���Ƿ���ܹ������ֵ�Ǵ���PEͷ�ĵڶ����ֶΣ�֮ǰĬ��90��λ��<DWORD>����ֻҪ��7�ı�������Ϊ���������ֹɱ��λ�����룬ͬʱ���Ҳ�����Ǳ�ı����������������

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
	tempSection->Characteristics = 0xE0000020; //�޸�exe����εĶ�дȨ��
 
	//���㣨Ԥ������������Ҫ�����Ĵ���Σ��ⲿ�ִ���β��ܽ��м��ܣ���Ϊ��ĵ�TLS���ܴ���
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
