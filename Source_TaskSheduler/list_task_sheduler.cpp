#pragma once

#define _WIN32_DCOM

#include <windows.h>
#include <iostream>
#include <comdef.h>
//  Include the task header file.
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

#include <stack>

#define ERROR    -1
#define NO_ERROR 0

extern int Get_Tasks_and_Statuses();

size_t TotalTasksCount = 0;

inline int Init_COM_and_Create_Task_Service_Instance(ITaskService **pService);
void Show_Task_State(TASK_STATE taskState);
void Show_Task_Names_and_Statuses(LONG numTasks, IRegisteredTaskCollection* pTaskCollection);
void Full_Stack_Folders(std::stack<ITaskFolder *> *stackFolders, ITaskFolderCollection *pSubFolders);
void Show_Subfolder_Tasks(std::stack<ITaskFolder *> *stackFolders);

inline int Init_COM_and_Create_Task_Service_Instance(ITaskService **pService)
{
	//  ------------------------------------------------------
	//  Initialize COM.
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		printf("CoInitializeEx failed: %x\n", hr);
		return ERROR;
	}

	//  Set general COM security levels.
	hr = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		0,
		NULL);

	if (FAILED(hr))
	{
		printf("CoInitializeSecurity failed: %x\n", hr);
		CoUninitialize();
		return 1;
	}

	//  ------------------------------------------------------
	//  Create an instance of the Task Service. 
	//ITaskService *pService = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(void**)pService);

	if (FAILED(hr))
	{
		printf("Failed to CoCreate an instance of the TaskService class: %x\n", hr);
		CoUninitialize();
		return ERROR;
	}

	//  Connect to the task service.
	hr = (*pService)->Connect(_variant_t(), _variant_t(),
		_variant_t(), _variant_t());

	if (FAILED(hr))
	{
		printf("ITaskService::Connect failed: %x\n", hr);
		(*pService)->Release();
		CoUninitialize();
		return ERROR;
	}
	//  ------------------------------------------------------

	return NO_ERROR;
}

void Show_Task_State(TASK_STATE taskState)
{
	switch (taskState)
	{
	case TASK_STATE_UNKNOWN:
		printf("\t\tState: UNKNOWN\n");
		break;
	case TASK_STATE_DISABLED:
		printf("\t\tState: DISABLED\n");
		break;
	case TASK_STATE_QUEUED:
		printf("\t\tState: QUEUED\n");
		break;
	case TASK_STATE_READY:
		printf("\t\tState: READY\n");
		break;
	case TASK_STATE_RUNNING:
		printf("\t\tState: RUNNING\n");
		break;
	}
}

void Show_Task_Names_and_Statuses(LONG numTasks, IRegisteredTaskCollection* pTaskCollection)
{
	HRESULT hr;

	TASK_STATE taskState;

	for (LONG i = 0; i < numTasks; i++)
	{
		IRegisteredTask* pRegisteredTask = NULL;
		hr = pTaskCollection->get_Item(_variant_t(i + 1), &pRegisteredTask);

		if (SUCCEEDED(hr))
		{
			BSTR taskName = NULL;
			hr = pRegisteredTask->get_Name(&taskName);
			if (SUCCEEDED(hr))
			{
				//++TotalTasksCount;

				// std::wcout << L"\tTask Name: " << (wchar_t*)(taskName) << std::endl;
				wprintf(L"\tTask Name: %ws\n", taskName);
				SysFreeString(taskName);

				hr = pRegisteredTask->get_State(&taskState);
				if (SUCCEEDED(hr))
				{
					//*
					if (taskState == TASK_STATE_READY)
					{
						printf("\t\tState: READY\n");
						++TotalTasksCount;
					}
					//*/
					if (taskState == TASK_STATE_RUNNING)
					{
						printf("\t\tState: RUNNING\n");
						++TotalTasksCount;
					}
					if (taskState == TASK_STATE_QUEUED)
					{
						printf("\t\tState: QUEUED\n");
						++TotalTasksCount;
					}
					//Show_Task_State(taskState);
				}
				else
					printf("\t\tCannot get the registered task state: %x\n", hr);
			}
			else
			{
				printf("Cannot get the registered task name: %x\n", hr);
			}
			pRegisteredTask->Release();
		}
		else
		{
			printf("Cannot get the registered task item at index=%ld: %x\n", i + 1, hr);
		}
	}
}

void Full_Stack_Folders(std::stack<ITaskFolder *> *stackFolders, ITaskFolderCollection *pSubFolders)
{
	long cntFolders = 0;

	HRESULT hr;

	hr = pSubFolders->get_Count(&cntFolders);

	if (FAILED(hr))
	{
		printf("Failed to get folders from collection\n");
		return;
	}

	for (long i = 0; i < cntFolders; i++)
	{
		ITaskFolder *pCurFolder = NULL;
		hr = pSubFolders->get_Item(_variant_t(i + 1), &pCurFolder);

		if (FAILED(hr))
		{
			printf("Failed to get current folder from folders collection\n");
			return;
		}

		stackFolders->push(pCurFolder);
	}
}

void Show_Subfolder_Tasks(std::stack<ITaskFolder *> *stackFolders)
{
	HRESULT hr;

	while (!stackFolders->empty())
	{
		ITaskFolder *pCurFolder = NULL;

		pCurFolder = stackFolders->top();
		stackFolders->pop();

		IRegisteredTaskCollection* pTaskCollection = NULL;
		hr = pCurFolder->GetTasks(NULL, &pTaskCollection);

		if (FAILED(hr))
		{
			pCurFolder->Release();
			printf("Cannot get the registered tasks.: %x\n", hr);
			CoUninitialize();
			return;
		}

		ITaskFolderCollection* pSubFolders = NULL;

		hr = pCurFolder->GetFolders(0, &pSubFolders);

		if (FAILED(hr))
		{
			printf("Cannot get the subfolders with tasks.: %x\n", hr);
			CoUninitialize();
			return;
		}

		BSTR pathToFolder;

		pCurFolder->get_Path(&pathToFolder);

		pCurFolder->Release();

		LONG numTasks = 0;
		hr = pTaskCollection->get_Count(&numTasks);

		// std::wcout << "'" << (wchar_t*)pathToFolder << "' Number of Tasks : " << numTasks << std::endl;
		wprintf(L"'%ws' Number of Tasks : %ld\n", (wchar_t*)pathToFolder, numTasks);

		SysFreeString(pathToFolder);

		Show_Task_Names_and_Statuses(numTasks, pTaskCollection);

		Full_Stack_Folders(stackFolders, pSubFolders);

		pSubFolders->Release();
		pTaskCollection->Release();
	}
}

inline int Get_Tasks_and_Statuses()
{
	HRESULT hr;

	ITaskService *pService = NULL;

	if (Init_COM_and_Create_Task_Service_Instance(&pService) == ERROR)
	{
		return ERROR;
	}

	//  Get the pointer to the root task folder.
	ITaskFolder *pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);

	pService->Release();
	if (FAILED(hr))
	{
		printf("Cannot get Root Folder pointer: %x\n", hr);
		CoUninitialize();
		return ERROR;
	}

	std::stack<ITaskFolder *> stackFolders;

	stackFolders.push(pRootFolder);

	Show_Subfolder_Tasks(&stackFolders);

	printf("Total count of tasks: %zd\n", TotalTasksCount);

	CoUninitialize();
	return NO_ERROR;
}
