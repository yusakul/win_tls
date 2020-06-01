//使用前应注意
//1. exe不能使用延迟加载的方式加载dll
//2. exe不能有重定位表
//3. 当前代码只解压代码段(即第一个区段)
//4. 程序需要引用除了kernel32.dll以外的dll 否则tls将不会被执行

#include <windows.h>
#include <stdio.h>

BOOL bAlreadyRun = FALSE; 
void NTAPI TLS_CALLBACK1(PVOID DllHandle,DWORD Reason,PVOID Reserved){
	if(bAlreadyRun == TRUE){ 
		return;
	}
	bAlreadyRun = TRUE;
	__asm { 
		jmp x1
			__emit 0x23
			__emit 0x15
			__emit 0x17
			__emit 0x13
			__emit 0x19
			__emit 0x15
			__emit 0x17
			__emit 0x33
			__emit 0x82
			__emit 0x75
			__emit 0x95
			__emit 0x16
x1:
	}
	
//************************DEFINE***************************	    
	DWORD RESERVEDLENGTH_L = 0x200;  
	//保护代码段的TLS本身解密代码不被加密的左侧预留长度（最大长度，实际可能是<=0x200）
    DWORD RESERVEDLENGTH_R = 0x1000;  
	//同上的右侧预留长度
    DWORD MARKDOKEY        = 0x7;    
	//用于标记是否加密过，这个值是存在PE头的第二个字段（之前默认90的位置<DWORD>），只要是7的倍数就认为处理过，防止杀软定位特征码，同时这个也可以是别的倍数，最好是素数。
	DWORD m_dwMarkKey[] = {0x13171523 ,0x33171519 ,0x16957582};
//************************DEFINE***************************	

	HANDLE hBase = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER pdhDos = NULL;
	PIMAGE_NT_HEADERS32 pntPeHead = NULL;
	IMAGE_FILE_HEADER* ifhFileHeader = NULL;
	DWORD dwPeSIze =0;
	PIMAGE_SECTION_HEADER pshTempSection = NULL;
	if (NULL == hBase)
	{
		MessageBox(NULL, L"hBase null", L"tit", MB_OK);
	}
	pdhDos = (PIMAGE_DOS_HEADER)hBase;
	if (NULL == pdhDos)
	{
		MessageBox(NULL, L"pdhDos null", L"tit", MB_OK);
	}
	pntPeHead = (PIMAGE_NT_HEADERS32)((DWORD)hBase + pdhDos->e_lfanew);
	if (NULL == pntPeHead)
	{
		MessageBox(NULL, L"pntPeHead null", L"tit", MB_OK);
	}
	ifhFileHeader = (IMAGE_FILE_HEADER*)&(pntPeHead->FileHeader);
	if (NULL == ifhFileHeader)
	{
		MessageBox(NULL, L"ifhFileHeader null", L"tit", MB_OK);
	}
	dwPeSIze = ifhFileHeader->SizeOfOptionalHeader;
	if (0 == dwPeSIze)
	{
		MessageBox(NULL, L"dwPeSIze null", L"tit", MB_OK);
	}
	pshTempSection = (PIMAGE_SECTION_HEADER)((DWORD)ifhFileHeader + 0x14 + dwPeSIze);
	if (NULL == pshTempSection)
	{
		MessageBox(NULL, L"pshTempSection null", L"tit", MB_OK);
	}


	
	//char *pPoint = &((char*)hBase)[2];
	//WORD wdRandKey = *((WORD*)pPoint); //0x90
	char* pPoint = ((char*)pntPeHead)-12;
	WORD wdRandKey = *((WORD*)pPoint); //0x90
	if(wdRandKey % MARKDOKEY != 0){
		//MessageBox(NULL ,L"tls_find not mark" ,L"tit" ,MB_OK);
	    return ;
	}

	
	//pPoint = &((char*)hBase)[4];
	pPoint = ((char*)pntPeHead)-10;
	WORD c32Key = *((DWORD*)pPoint);   //0x3

	if(c32Key == 11){
		//MessageBox(NULL ,L"tls_KeyIs11" ,L"tit" ,MB_OK);
	}

	DWORD dwTextStartAddress = (DWORD)hBase + pshTempSection->VirtualAddress;
	DWORD dwTextEndAddress = (DWORD)hBase + pshTempSection->VirtualAddress + pshTempSection->Misc.VirtualSize;

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
      //MessageBox(NULL ,L"tls_find not key" ,L"tit" ,MB_OK);
	  return ;
	}

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
	//MessageBox(NULL ,L"tls_mark" ,L"tit" ,MB_OK);
}




#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")

EXTERN_C

#pragma data_seg (".CRT$XLB")
PIMAGE_TLS_CALLBACK _tls_callback = TLS_CALLBACK1;
#pragma data_seg ()