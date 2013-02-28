#include "RemoteThreadDll.h"


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


//======================================================== =============================//
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
	//对于从参数 pRemotePara 中传过来的 API 都需要重新声明
	typedef HMODULE (WINAPI *LOADLIBRARY_ZACHARY)(LPCSTR);
	typedef BOOL (WINAPI *FREELIBRARY_ZACHARY)(HMODULE);
	typedef FARPROC (WINAPI *GETPROCADDRESS_ZACHARY)(HMODULE hModule, LPCSTR lpProcName);

	//这两个 API 是由 ZacharyDLL.dll 导出的，也需要重新声明
	typedef void (* PRINTMESSAGEBOX_ZACHARY)();
	typedef void (* PRINTDEBUGSTRING)();

	LOADLIBRARY_ZACHARY LoadLibrary_Zachary;
	FREELIBRARY_ZACHARY FreeLibrary_Zachary;
	GETPROCADDRESS_ZACHARY GetProcAddress_Zachary;
	PRINTMESSAGEBOX_ZACHARY PrintMessageBox_Zachary;
	PRINTDEBUGSTRING PrintDebugString_Zachary;

	//在参数 pRemotePara 中保存了 LoadLibray,FreeLibrary 和 GetProcAddress 这三个 API 的地址
	LoadLibrary_Zachary = (LOADLIBRARY_ZACHARY)pRemotePara->m_dwLoadLibraryAddr;
	FreeLibrary_Zachary = (FREELIBRARY_ZACHARY)pRemotePara->m_dwFreeLibraryAddr;
	GetProcAddress_Zachary = (GETPROCADDRESS_ZACHARY)pRemotePara->m_dwGetProcAddrAddr;

	//获得 DLL 所在的地址
	PCHAR pDllPath = pRemotePara->m_strDllPath;

	//加载我们自己的 DLL - ZacharyDLL.dll
	HMODULE hMyDll = LoadLibrary_Zachary(pDllPath);

	if(NULL != hMyDll)
	{
		//从 ZacharyDll.dll 中通过 GetProcAddress 获取 DLL 导出的 API 的地址
		PrintDebugString_Zachary = (PRINTDEBUGSTRING)GetProcAddress_Zachary(hMyDll, pRemotePara->m_printDbgStr);
		PrintMessageBox_Zachary = (PRINTMESSAGEBOX_ZACHARY)GetProcAddress_Zachary(hMyDll, pRemotePara->m_printMsgBox);

		//执行 DLL 中所导出的 API
		PrintDebugString_Zachary();
		PrintMessageBox_Zachary();
		//释放所加载的 DLL
		FreeLibrary_Zachary(hMyDll);
	}
	return 0;
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
				HMODULE hKernel32 = GetModuleHandle("Kernel32");
				if(NULL == hKernel32)
				{
					OutputErrorMessage("main - GetModuleHandle Failed , Error Code Is %d , Error Message Is %s !");

					//释放 VirtualAllocEx 分配的内存
					VirtualFreeEx(hProcess, pRemoteThread, 0, MEM_RELEASE);
					CloseHandle(hProcess);
				}
				else
				{
					RemotePara remotePara;
					ZeroMemory(&remotePara, sizeof(RemotePara));

					//将 LoadLibraryA、FreeLibrary 和 GetProcAddress 三个 Kernel32 API 的地址保存到 remotePara 中
					remotePara.m_dwLoadLibraryAddr = (DWORD)GetProcAddress(hKernel32, "LoadLibraryA");
					remotePara.m_dwFreeLibraryAddr = (DWORD)GetProcAddress(hKernel32, "FreeLibrary");
					remotePara.m_dwGetProcAddrAddr = (DWORD)GetProcAddress(hKernel32, "GetProcAddress");

					string strMsgBox = "PrintMessageBox";
					string strBbgStr = "PrintDebugString";

					CHAR tmpArray[MAX_PATH];
					CHAR * pTmpMsgBoxArray = "PrintMessageBox";
					CHAR * pTmpDbgStrArray = "PrintDebugString";
					
					//将 ZacharyDll.dll 中导出的 API 的名称保存到 remotePara 中
					strcpy(remotePara.m_printMsgBox, pTmpMsgBoxArray);
					strcpy(remotePara.m_printDbgStr, pTmpDbgStrArray);

					ZeroMemory(tmpArray, MAX_PATH);

					//获取到当前路径
					GetCurrentDirectory(MAX_PATH, tmpArray);
					
					//路径加上 DLL 名称(从而可以将 DLL 和 Loader EXE 放在同一个目录下运行了)
					//免去了将 DLL 复制到系统目录下的麻烦
					string strDllPath = tmpArray;
					strDllPath += DLLNAME;

					//将 DLL 的路径完整的复制到 remotePara 中
					strcpy(remotePara.m_strDllPath, strDllPath.c_str());
					//free(tmpArray);

					//在宿主进程中分配虚拟内存来容纳远程线程所需要的参数
					PVOID pRemotePara = VirtualAllocEx(hProcess, NULL, sizeof(RemotePara), MEM_COMMIT, PAGE_READWRITE);
					if(NULL == pRemotePara)
					{
						OutputErrorMessage("main - VirtualAllocEx Failed , Error Code Is %d , Error Message Is %s !");

						//释放 VirtualAllocEx 分配的内存
						VirtualFreeEx(hProcess, pRemoteThread, 0, MEM_RELEASE);
						CloseHandle(hProcess);
					}
					else
					{
						//将远程线程所携带的参数写入到宿主进程中所分配的虚拟内存
						if(NULL == WriteProcessMemory(hProcess, pRemotePara, &remotePara, sizeof(RemotePara), 0))
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

							//开始创建远程线程
							hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteThread, pRemotePara, 0, &dwThreadId);
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
	}

	cout<<endl<<endl;
	system("pause");
	return 0;
}