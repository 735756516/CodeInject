#include "ZacharyDll.h"

BOOL WINAPI DllMain(HANDLE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}

	return TRUE;
}

//弹出一个对话框
void PrintMessageBox()
{
	MessageBox(NULL, MESSAGE_CONTENT, MESSAGE_TITLE, MB_OK);
}

//打印语句
void PrintDebugString()
{
	//直接打印出 5 条同样的消息
	for(int i=0; i<5; i++)
	{
		OutputDebugString("In ZacharyDll - PrintDebugString !");
	}
}
