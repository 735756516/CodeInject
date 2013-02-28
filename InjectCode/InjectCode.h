#ifndef __INJECT_CODE_H__
#define __INJECT_CODE_H__


//////////////////////////////////////////////////////////////////////////
/////////��������ֻ�ܹ��� Release �汾�±������У��� Debug ���޷��ɹ�����/////////
//////////////////////////////////////////////////////////////////////////


#include <Windows.h>
#include <iostream>
#include <tchar.h>
#include <strsafe.h>
#include <Psapi.h>
#include <string>

using namespace std;

#pragma comment(lib, "Psapi.lib")

typedef struct _REMOTE_PARAMETER
{
	CHAR m_msgContent[MAX_PATH];
	CHAR m_msgTitle[MAX_PATH];
	DWORD m_dwMessageBoxAddr;

}RemotePara, * PRemotePara;

bool OutputErrorMessage(LPTSTR lpszMsg);

bool OutputSuccessMessage(LPTSTR lpszMsg);

bool AdjustProcessTokenPrivilege();

bool ProcessIsExplorer(DWORD dwProcessId);

void GetMessageBoxParameter(PRemotePara pRemotePara);

DWORD WINAPI RemoteThreadProc(PRemotePara pRemotePara);


#endif	// end of __INJECT_CODE_H__