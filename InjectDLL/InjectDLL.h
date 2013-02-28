#ifndef __INJECT_DLL_H__
#define __INJECT_DLL_H__

#include <Windows.h>
#include <iostream>
#include <tchar.h>
#include <Psapi.h>
#include <strsafe.h>
#include <string>

using namespace std;

#pragma comment(lib, "Psapi.lib")


#define DLLNAME "\\MyDLL.dll\0"


typedef struct _REMOTE_PARAMETER
{
	CHAR m_printMsgBox[MAX_PATH];
	CHAR m_printDbgStr[MAX_PATH];
	CHAR m_strDllPath[MAX_PATH];
	DWORD m_dwLoadLibraryAddr;
	DWORD m_dwFreeLibraryAddr;
	DWORD m_dwGetProcAddrAddr;

}RemotePara, * PRemotePara;


DWORD WINAPI RemoteThreadProc(PRemotePara pRemotePara);

bool OutputErrorMessage(LPTSTR lpszMsg);

bool OutputSuccessMessage(LPTSTR lpszMsg);

bool AdjustProcessTokenPrivilege();


#endif	// end of __INJECT_DLL_H__