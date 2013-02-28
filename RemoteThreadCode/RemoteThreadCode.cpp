#include "RemoteThreadCode.h"


//=====================================================================================//
//Name: bool OutputErrorMessage()                                                      //
//                                                                                     //
//Descripion: 打印出当前程序代码中 GetLastError 所代表的错误，表示失败  		               //
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
//Descripion: 实现打印一条消息，用来显示操作成功	    							     	   //
//=====================================================================================//
bool OutputSuccessMessage(LPTSTR lpszMsg)
{
	OutputDebugString(lpszMsg);

	return TRUE;
}


//=====================================================================================//
//Name: bool AdjustProcessTokenPrivilege()                                             //
//                                                                                     //
//Descripion: 提升当前进程权限										  		               //
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
//Descripion: 远程线程处理例程										  		               //
//=====================================================================================//
DWORD WINAPI RemoteThreadProc(PRemotePara pRemotePara)
{
	//这个 MessageBox 的地址必须由外部参数传入，因为在其他进程中需要重定向
	typedef int (WINAPI *MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

	MESSAGEBOXA MessageBoxA;
	MessageBoxA = (MESSAGEBOXA)pRemotePara->m_dwMessageBoxAddr;

	//调用 MessageBoxA 来打印消息
	MessageBoxA(NULL, pRemotePara->m_msgContent, pRemotePara->m_msgTitle, MB_OK);

	return 0;
}


//=====================================================================================//
//Name: void GetMessageBoxParameter(PRemotePara pRemotePara)                           //
//                                                                                     //
//Descripion: 获得 MessageBox 这个 API 的地址以及填充的参数			  		               //
//=====================================================================================//
void GetMessageBoxParameter(PRemotePara pRemotePara)
{
	HMODULE hUser32 = LoadLibrary("User32.dll");
	
	pRemotePara->m_dwMessageBoxAddr = (DWORD)GetProcAddress(hUser32, "MessageBoxA");
	strcat(pRemotePara->m_msgContent, "Hello, Zachary.XiaoZhen !\0");
	strcat(pRemotePara->m_msgTitle, "Hello\0");
	
	//注意要释放掉 User32
	FreeLibrary(hUser32);
}


//=====================================================================================//
//Name: bool ProcessIsExplorer(DWORD dwProcessId)                                      //
//                                                                                     //
//Descripion: 判定一个进程是否为 Explorer 进程						  		               //
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
	//定义线程的大小为 4K
	const DWORD THREAD_SIZE = 1024 * 4;

	DWORD dwProcess[512];
	DWORD dwNeeded;
	DWORD dwExplorerId;
	HANDLE hProcess;

	memset(dwProcess, 0, sizeof(DWORD) * 512);

	//提升当前进程的权限
	AdjustProcessTokenPrivilege();

	//第一个参数为用来保存所有的进程 ID
	//第二个参数则是第一个参数的字节数
	//第三个参数则是写入 dwProcess 数组的字节数
	EnumProcesses(dwProcess, sizeof(dwProcess), &dwNeeded);

	//找到 explorer.exe 进程的 ID
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
		//在 hProcess 所代表的进程内部分配虚拟内存来容纳我们将要创建的远程线程
		PVOID pRemoteThread = VirtualAllocEx(hProcess, NULL, THREAD_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if(NULL == pRemoteThread)
		{
			OutputErrorMessage("main - VirtualAllocEx Failed , Error Code Is %d , Error Message Is %s !");

			//关闭进程句柄
			CloseHandle(hProcess);
		}
		else
		{
			//往我们在 hProcess 进程中分配的虚拟内存里面写入数据，这里主要是将整个线程都写进去
			if(WriteProcessMemory(hProcess, pRemoteThread, &RemoteThreadProc, THREAD_SIZE, 0) == FALSE)
			{
				OutputErrorMessage("main - WriteProcessMemory Failed , Error Code Is %d , Error Message Is %s !");

				//释放 VirtualAllocEx 分配的内存
				VirtualFreeEx(hProcess, pRemoteThread, 0, MEM_RELEASE);
				CloseHandle(hProcess);
			}
			else
			{
				RemotePara remotePara;
				ZeroMemory(&remotePara, sizeof(RemotePara));
				GetMessageBoxParameter(&remotePara);

				//在 hProcess 所代表的进程中分配虚拟内存来容纳线程的参数部分
				PRemotePara pRemotePara = (PRemotePara)VirtualAllocEx(hProcess, NULL, sizeof(RemotePara), MEM_COMMIT, PAGE_READWRITE);
				if(NULL == pRemotePara)
				{
					OutputErrorMessage("main - VirtualAllocEx Failed , Error Code Is %d , Error Message Is %s !");

					//释放 VirtualAllocEx 分配的内存
					VirtualFreeEx(hProcess, pRemoteThread, 0, MEM_RELEASE);
					CloseHandle(hProcess);
				}
				else
				{
					//往在 hProcess 进程中分配的虚拟内存中写入参数数据
					if(WriteProcessMemory(hProcess, pRemotePara, &remotePara, sizeof(RemotePara), 0) == FALSE)
					{
						OutputErrorMessage("main - WriteProcessMemory Failed , Error Code Is %d , Error Message Is %s !");
						//释放 VirtualAllocEx 分配的内存
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

						//将已经写入到 hProcess 进程中的线程以及线程的参数作为 CreateRemoteThread 的参数，从而创建远程线程
						hThread = CreateRemoteThread(hProcess, NULL, 0, (DWORD (WINAPI *)(LPVOID))pRemoteThread, pRemotePara, 0, &dwThreadId);
						if(NULL == hThread)
						{
							OutputErrorMessage("main - CreateRemoteThread Failed , Error Code Is %d , Error Message Is %s !");
						}
						else
						{
							OutputSuccessMessage("Code Inject Success !");
						}

						//等待远程线程结束
						WaitForSingleObject(hThread, INFINITE);
						CloseHandle(hThread);

						//必须等到远程线程结束后才能释放宿主进程中所分配的内存，否则宿主进程会直接崩溃
						//释放 VirtualAllocEx 分配的内存
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