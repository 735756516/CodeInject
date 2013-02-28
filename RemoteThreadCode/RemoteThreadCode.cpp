#include "RemoteThreadCode.h"


//=====================================================================================//
//Name: bool OutputErrorMessage()                                                      //
//                                                                                     //
//Descripion: ��ӡ����ǰ��������� GetLastError ������Ĵ��󣬱�ʾʧ��  		               //
//=====================================================================================//
bool OutputErrorMessage(LPTSTR lpszMsg)
{
	LPVOID lpszBufMsg;
	LPVOID lpszBufErrorMsg;
	DWORD dwError = GetLastError();

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, dwError, 
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpszBufErrorMsg, 0, NULL);

	lpszBufMsg = (LPVOID)LocalAlloc(LMEM_ZEROINIT, sizeof(TCHAR) * 256);
	StringCchPrintf((LPTSTR)lpszBufMsg, LocalSize(lpszBufMsg), _TEXT(lpszMsg), dwError, lpszBufErrorMsg);

	OutputDebugString((LPTSTR)lpszBufMsg);

	LocalFree(lpszBufMsg);

	return FALSE;
}


//=====================================================================================//
//Name: bool OutputSuccessMessage()                                                    //
//                                                                                     //
//Descripion: ʵ�ִ�ӡһ����Ϣ��������ʾ�����ɹ�	    							     	   //
//=====================================================================================//
bool OutputSuccessMessage(LPTSTR lpszMsg)
{
	OutputDebugString(lpszMsg);

	return TRUE;
}


//=====================================================================================//
//Name: bool AdjustProcessTokenPrivilege()                                             //
//                                                                                     //
//Descripion: ������ǰ����Ȩ��										  		               //
//=====================================================================================//
bool AdjustProcessTokenPrivilege()
{
	LUID luidTmp;
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		OutputDebugString("AdjustProcessTokenPrivilege OpenProcessToken Failed ! \n");

		return false;
	}

	if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidTmp))
	{
		OutputDebugString("AdjustProcessTokenPrivilege LookupPrivilegeValue Failed ! \n");

		CloseHandle(hToken);

		return FALSE;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luidTmp;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if(!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
	{
		OutputDebugString("AdjustProcessTokenPrivilege AdjustTokenPrivileges Failed ! \n");

		CloseHandle(hToken);

		return FALSE;
	}
	return true;
}


//=====================================================================================//
//Name: bool RemoteThreadProc(LPVOID lpParameter)                                      //
//                                                                                     //
//Descripion: Զ���̴߳�������										  		               //
//=====================================================================================//
DWORD WINAPI RemoteThreadProc(PRemotePara pRemotePara)
{
	//��� MessageBox �ĵ�ַ�������ⲿ�������룬��Ϊ��������������Ҫ�ض���
	typedef int (WINAPI *MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

	MESSAGEBOXA MessageBoxA;
	MessageBoxA = (MESSAGEBOXA)pRemotePara->m_dwMessageBoxAddr;

	//���� MessageBoxA ����ӡ��Ϣ
	MessageBoxA(NULL, pRemotePara->m_msgContent, pRemotePara->m_msgTitle, MB_OK);

	return 0;
}


//=====================================================================================//
//Name: void GetMessageBoxParameter(PRemotePara pRemotePara)                           //
//                                                                                     //
//Descripion: ��� MessageBox ��� API �ĵ�ַ�Լ����Ĳ���			  		               //
//=====================================================================================//
void GetMessageBoxParameter(PRemotePara pRemotePara)
{
	HMODULE hUser32 = LoadLibrary("User32.dll");
	
	pRemotePara->m_dwMessageBoxAddr = (DWORD)GetProcAddress(hUser32, "MessageBoxA");
	strcat(pRemotePara->m_msgContent, "Hello, Zachary.XiaoZhen !\0");
	strcat(pRemotePara->m_msgTitle, "Hello\0");
	
	//ע��Ҫ�ͷŵ� User32
	FreeLibrary(hUser32);
}


//=====================================================================================//
//Name: bool ProcessIsExplorer(DWORD dwProcessId)                                      //
//                                                                                     //
//Descripion: �ж�һ�������Ƿ�Ϊ Explorer ����						  		               //
//=====================================================================================//
bool ProcessIsExplorer(DWORD dwProcessId)
{
	HANDLE hProcess;

	hProcess = NULL;

	hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
	if(NULL == hProcess)
	{
		OutputErrorMessage("ProcessIsExplorer - OpenProcess Failed , Error Code Is %d , Error Message Is %s !");

		return FALSE;
	}

	DWORD dwNameLen;
	TCHAR pathArray[MAX_PATH];
	ZeroMemory(pathArray, MAX_PATH);

	dwNameLen = 0;
	dwNameLen = GetModuleFileNameEx(hProcess, NULL, pathArray, MAX_PATH);
	if(dwNameLen == 0)
	{
		OutputErrorMessage("ProcessIsExplorer - GetModuleFileNameEx Failed , Error Code Is %d , Error Message Is %s !");
		CloseHandle(hProcess);

		return FALSE;
	}

	TCHAR exeNameArray[MAX_PATH];
	ZeroMemory(exeNameArray, MAX_PATH);
	_tsplitpath(pathArray, NULL, NULL, exeNameArray, NULL);

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
	//�����̵߳Ĵ�СΪ 4K
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
		OutputErrorMessage("main - OpenProcess Failed , Error Code Is %d , Error Message Is %s !");
	}
	else
	{
		//�� hProcess ������Ľ����ڲ����������ڴ����������ǽ�Ҫ������Զ���߳�
		PVOID pRemoteThread = VirtualAllocEx(hProcess, NULL, THREAD_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if(NULL == pRemoteThread)
		{
			OutputErrorMessage("main - VirtualAllocEx Failed , Error Code Is %d , Error Message Is %s !");

			//�رս��̾��
			CloseHandle(hProcess);
		}
		else
		{
			//�������� hProcess �����з���������ڴ�����д�����ݣ�������Ҫ�ǽ������̶߳�д��ȥ
			if(WriteProcessMemory(hProcess, pRemoteThread, &RemoteThreadProc, THREAD_SIZE, 0) == FALSE)
			{
				OutputErrorMessage("main - WriteProcessMemory Failed , Error Code Is %d , Error Message Is %s !");

				//�ͷ� VirtualAllocEx ������ڴ�
				VirtualFreeEx(hProcess, pRemoteThread, 0, MEM_RELEASE);
				CloseHandle(hProcess);
			}
			else
			{
				RemotePara remotePara;
				ZeroMemory(&remotePara, sizeof(RemotePara));
				GetMessageBoxParameter(&remotePara);

				//�� hProcess ������Ľ����з��������ڴ��������̵߳Ĳ�������
				PRemotePara pRemotePara = (PRemotePara)VirtualAllocEx(hProcess, NULL, sizeof(RemotePara), MEM_COMMIT, PAGE_READWRITE);
				if(NULL == pRemotePara)
				{
					OutputErrorMessage("main - VirtualAllocEx Failed , Error Code Is %d , Error Message Is %s !");

					//�ͷ� VirtualAllocEx ������ڴ�
					VirtualFreeEx(hProcess, pRemoteThread, 0, MEM_RELEASE);
					CloseHandle(hProcess);
				}
				else
				{
					//���� hProcess �����з���������ڴ���д���������
					if(WriteProcessMemory(hProcess, pRemotePara, &remotePara, sizeof(RemotePara), 0) == FALSE)
					{
						OutputErrorMessage("main - WriteProcessMemory Failed , Error Code Is %d , Error Message Is %s !");
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

						//���Ѿ�д�뵽 hProcess �����е��߳��Լ��̵߳Ĳ�����Ϊ CreateRemoteThread �Ĳ������Ӷ�����Զ���߳�
						hThread = CreateRemoteThread(hProcess, NULL, 0, (DWORD (WINAPI *)(LPVOID))pRemoteThread, pRemotePara, 0, &dwThreadId);
						if(NULL == hThread)
						{
							OutputErrorMessage("main - CreateRemoteThread Failed , Error Code Is %d , Error Message Is %s !");
						}
						else
						{
							OutputSuccessMessage("Code Inject Success !");
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

	cout<<endl<<endl;
	system("pause");
	return 0;
}