#include "InjectDLL.h"


/************************************************************************/
/* ��ӡ����ǰ��������� GetLastError ������Ĵ��󣬱�ʾʧ��
/************************************************************************/
bool OutputErrorMessage(LPTSTR lpszMsg)
{
	LPVOID lpszBufMsg;
	LPVOID lpszBufErrorMsg;
	DWORD dwError = GetLastError();

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, dwError, 
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpszBufErrorMsg, 0, NULL);

	lpszBufMsg = (LPVOID)LocalAlloc(LMEM_ZEROINIT, sizeof(TCHAR) * 256);
	StringCchPrintf((LPTSTR)lpszBufMsg, LocalSize(lpszBufMsg), (lpszMsg), dwError, lpszBufErrorMsg);

	OutputDebugString((LPTSTR)lpszBufMsg);

	LocalFree(lpszBufMsg);

	return FALSE;
}


/************************************************************************/
/* ʵ�ִ�ӡһ����Ϣ��������ʾ�����ɹ�
/************************************************************************/
bool OutputSuccessMessage(LPTSTR lpszMsg)
{
	OutputDebugString(lpszMsg);

	return TRUE;
}


/************************************************************************/
/* ������ǰ����Ȩ��
/************************************************************************/
bool AdjustProcessTokenPrivilege()
{
	LUID luidTmp;
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		OutputDebugString(TEXT("AdjustProcessTokenPrivilege OpenProcessToken Failed ! \n"));

		return false;
	}

	if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidTmp))
	{
		OutputDebugString(TEXT("AdjustProcessTokenPrivilege LookupPrivilegeValue Failed ! \n"));

		CloseHandle(hToken);

		return FALSE;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luidTmp;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if(!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
	{
		OutputDebugString(TEXT("AdjustProcessTokenPrivilege AdjustTokenPrivileges Failed ! \n"));

		CloseHandle(hToken);

		return FALSE;
	}
	return true;
}


/************************************************************************/
/* Զ���̴߳�������
/************************************************************************/
DWORD WINAPI RemoteThreadProc(PRemotePara pRemotePara)
{
	//���ڴӲ��� pRemotePara �д������� API ����Ҫ��������
	typedef HMODULE (WINAPI *LOADLIBRARY)(LPCSTR);
	typedef BOOL (WINAPI *FREELIBRARY)(HMODULE);
	typedef FARPROC (WINAPI *GETPROCADDRESS)(HMODULE hModule, LPCSTR lpProcName);

	//������ API ���� ZacharyDLL.dll �����ģ�Ҳ��Ҫ��������
	typedef void (* PRINTMESSAGEBOX)();
	typedef void (* PRINTDEBUGSTRING)();

	LOADLIBRARY MyLoadLibrary;
	FREELIBRARY MyFreeLibrary;
	GETPROCADDRESS MyGetProcAddress;
	PRINTMESSAGEBOX MyPrintMessageBox;
	PRINTDEBUGSTRING MyPrintDebugString;

	//�ڲ��� pRemotePara �б����� LoadLibray,FreeLibrary �� GetProcAddress ������ API �ĵ�ַ
	MyLoadLibrary = (LOADLIBRARY)pRemotePara->m_dwLoadLibraryAddr;
	MyFreeLibrary = (FREELIBRARY)pRemotePara->m_dwFreeLibraryAddr;
	MyGetProcAddress = (GETPROCADDRESS)pRemotePara->m_dwGetProcAddrAddr;

	//��� DLL ���ڵĵ�ַ
	PCHAR pDllPath = pRemotePara->m_strDllPath;

	//���������Լ��� DLL - ZacharyDLL.dll
	HMODULE hMyDll = MyLoadLibrary(pDllPath);

	if(NULL != hMyDll)
	{
		//�� ZacharyDll.dll ��ͨ�� GetProcAddress ��ȡ DLL ������ API �ĵ�ַ
		MyPrintDebugString = (PRINTDEBUGSTRING)MyGetProcAddress(hMyDll, pRemotePara->m_printDbgStr);
		MyPrintMessageBox = (PRINTMESSAGEBOX)MyGetProcAddress(hMyDll, pRemotePara->m_printMsgBox);

		//ִ�� DLL ���������� API
		MyPrintDebugString();
		MyPrintMessageBox();
		//�ͷ������ص� DLL
		MyFreeLibrary(hMyDll);
	}
	return 0;
}


/************************************************************************/
/* �ж�һ�������Ƿ�Ϊ Explorer ����
/************************************************************************/
bool ProcessIsExplorer(DWORD dwProcessId)
{
	HANDLE hProcess;

	hProcess = NULL;

	hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
	if(NULL == hProcess)
	{
		OutputErrorMessage(TEXT("ProcessIsExplorer - OpenProcess Failed , Error Code Is %d , Error Message Is %s !"));

		return FALSE;
	}

	DWORD dwNameLen;
	CHAR pathArray[MAX_PATH];
	ZeroMemory(pathArray, MAX_PATH);

	dwNameLen = 0;
	dwNameLen = GetModuleFileNameExA(hProcess, NULL, pathArray, MAX_PATH);
	if(dwNameLen == 0)
	{
		OutputErrorMessage(TEXT("ProcessIsExplorer - GetModuleFileNameEx Failed , Error Code Is %d , Error Message Is %s !"));
		CloseHandle(hProcess);

		return FALSE;
	}

	CHAR exeNameArray[MAX_PATH];
	ZeroMemory(exeNameArray, MAX_PATH);
	_splitpath(pathArray, NULL, NULL, exeNameArray, NULL);

	string str1 = exeNameArray;
	if((str1.compare("Explorer") == 0) || (str1.compare("explorer") == 0))
	{
		CloseHandle(hProcess);

		return TRUE;
	}

	return FALSE;
}


int main()
{
	const DWORD THREAD_SIZE = 1024 * 4;
	DWORD dwProcess[512];
	DWORD dwNeeded;
	DWORD dwExplorerId;
	HANDLE hProcess;

	memset(dwProcess, 0, sizeof(DWORD) * 512);

	//������ǰ���̵�Ȩ��
	AdjustProcessTokenPrivilege();

	//��һ������Ϊ�����������еĽ��� ID
	//�ڶ����������ǵ�һ���������ֽ���
	//��������������д�� dwProcess ������ֽ���
	EnumProcesses(dwProcess, sizeof(dwProcess), &dwNeeded);

	//�ҵ� explorer.exe ���̵� ID
	dwExplorerId = 0;
	for(int i = 0; i < dwNeeded / sizeof(DWORD); i++)
	{
		if(0 != dwProcess[i])
		{
			if(ProcessIsExplorer(dwProcess[i]))
			{
				dwExplorerId = dwProcess[i];
				break;
			}
		}
	}

	hProcess = NULL;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwExplorerId);
	if(NULL == hProcess)
	{
		OutputErrorMessage(TEXT("main - OpenProcess Failed , Error Code Is %d , Error Message Is %s !"));
	}
	else
	{
		//�� hProcess ������Ľ����ڲ����������ڴ����������ǽ�Ҫ������Զ���߳�
		PVOID pRemoteThread = VirtualAllocEx(hProcess, NULL, THREAD_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if(NULL == pRemoteThread)
		{
			OutputErrorMessage(TEXT("main - VirtualAllocEx Failed , Error Code Is %d , Error Message Is %s !"));

			//�رս��̾��
			CloseHandle(hProcess);
		}
		else
		{
			//�������� hProcess �����з���������ڴ�����д�����ݣ�������Ҫ�ǽ������̶߳�д��ȥ
			if(WriteProcessMemory(hProcess, pRemoteThread, &RemoteThreadProc, THREAD_SIZE, 0) == FALSE)
			{
				OutputErrorMessage(TEXT("main - WriteProcessMemory Failed , Error Code Is %d , Error Message Is %s !"));

				//�ͷ� VirtualAllocEx ������ڴ�
				VirtualFreeEx(hProcess, pRemoteThread, 0, MEM_RELEASE);
				CloseHandle(hProcess);
			}
			else
			{
				HMODULE hKernel32 = GetModuleHandle(TEXT("Kernel32"));
				if(NULL == hKernel32)
				{
					OutputErrorMessage(TEXT("main - GetModuleHandle Failed , Error Code Is %d , Error Message Is %s !"));

					//�ͷ� VirtualAllocEx ������ڴ�
					VirtualFreeEx(hProcess, pRemoteThread, 0, MEM_RELEASE);
					CloseHandle(hProcess);
				}
				else
				{
					RemotePara remotePara;
					ZeroMemory(&remotePara, sizeof(RemotePara));

					//�� LoadLibraryA��FreeLibrary �� GetProcAddress ���� Kernel32 API �ĵ�ַ���浽 remotePara ��
					remotePara.m_dwLoadLibraryAddr = (DWORD)GetProcAddress(hKernel32, "LoadLibraryA");
					remotePara.m_dwFreeLibraryAddr = (DWORD)GetProcAddress(hKernel32, "FreeLibrary");
					remotePara.m_dwGetProcAddrAddr = (DWORD)GetProcAddress(hKernel32, "GetProcAddress");

					string strMsgBox = "PrintMessageBox";
					string strBbgStr = "PrintDebugString";

					CHAR tmpArray[MAX_PATH];
					CHAR * pTmpMsgBoxArray = "PrintMessageBox";
					CHAR * pTmpDbgStrArray = "PrintDebugString";
					
					//�� ZacharyDll.dll �е����� API �����Ʊ��浽 remotePara ��
					strcpy(remotePara.m_printMsgBox, pTmpMsgBoxArray);
					strcpy(remotePara.m_printDbgStr, pTmpDbgStrArray);

					ZeroMemory(tmpArray, MAX_PATH);

					//��ȡ����ǰ·��
					GetCurrentDirectoryA(MAX_PATH, tmpArray);
					
					//·������ DLL ����(�Ӷ����Խ� DLL �� Loader EXE ����ͬһ��Ŀ¼��������)
					//��ȥ�˽� DLL ���Ƶ�ϵͳĿ¼�µ��鷳
					string strDllPath = tmpArray;
					strDllPath += DLLNAME;

					//�� DLL ��·�������ĸ��Ƶ� remotePara ��
					strcpy(remotePara.m_strDllPath, strDllPath.c_str());
					//free(tmpArray);

					//�����������з��������ڴ�������Զ���߳�����Ҫ�Ĳ���
					PVOID pRemotePara = VirtualAllocEx(hProcess, NULL, sizeof(RemotePara), MEM_COMMIT, PAGE_READWRITE);
					if(NULL == pRemotePara)
					{
						OutputErrorMessage(TEXT("main - VirtualAllocEx Failed , Error Code Is %d , Error Message Is %s !"));

						//�ͷ� VirtualAllocEx ������ڴ�
						VirtualFreeEx(hProcess, pRemoteThread, 0, MEM_RELEASE);
						CloseHandle(hProcess);
					}
					else
					{
						//��Զ���߳���Я���Ĳ���д�뵽����������������������ڴ�
						if(NULL == WriteProcessMemory(hProcess, pRemotePara, &remotePara, sizeof(RemotePara), 0))
						{
							OutputErrorMessage(TEXT("main - WriteProcessMemory Failed , Error Code Is %d , Error Message Is %s !"));

							//�ͷ� VirtualAllocEx ������ڴ�
							VirtualFreeEx(hProcess, pRemoteThread, 0, MEM_RELEASE);
							VirtualFreeEx(hProcess, pRemotePara, 0, MEM_RELEASE);
							CloseHandle(hProcess);
						}
						else
						{
							HANDLE hThread;
							DWORD dwThreadId;

							hThread = NULL;
							dwThreadId = 0;

							//��ʼ����Զ���߳�
							hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteThread, pRemotePara, 0, &dwThreadId);
							if(NULL == hThread)
							{
								OutputErrorMessage(TEXT("main - CreateRemoteThread Failed , Error Code Is %d , Error Message Is %s !"));
							}
							else
							{
								OutputSuccessMessage(TEXT("Code Inject Success !"));
							}

							//�ȴ�Զ���߳̽���
							WaitForSingleObject(hThread, INFINITE);
							CloseHandle(hThread);

							//����ȵ�Զ���߳̽���������ͷ�������������������ڴ棬�����������̻�ֱ�ӱ���
							//�ͷ� VirtualAllocEx ������ڴ�
							VirtualFreeEx(hProcess, pRemoteThread, 0, MEM_RELEASE);
							VirtualFreeEx(hProcess, pRemotePara, 0, MEM_RELEASE);

							CloseHandle(hProcess);
						}
					}
				}
			}
		}
	}

	cout<<endl<<endl;
	system("pause");
	return 0;
}