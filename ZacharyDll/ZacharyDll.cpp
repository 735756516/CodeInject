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

//����һ���Ի���
void PrintMessageBox()
{
	MessageBox(NULL, MESSAGE_CONTENT, MESSAGE_TITLE, MB_OK);
}

//��ӡ���
void PrintDebugString()
{
	//ֱ�Ӵ�ӡ�� 5 ��ͬ������Ϣ
	for(int i=0; i<5; i++)
	{
		OutputDebugString("In ZacharyDll - PrintDebugString !");
	}
}
