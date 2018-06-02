#include "task_sheduler.h"

#define TASK_NAME_PING L"Event_PING_Trigger_Task"

#define LOG_PATH_TASK L"<QueryList><Query Id='0' Path='Security'><Select Path='Security'>*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=5152]]</Select></Query></QueryList>"

#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)

#define VARIABLE_EVENT_ID event_id
#define VARIABLE_EVENT_IP event_ip

#define ARG_VARIABLE_EVENT L"$(" STRINGIZE(VARIABLE_EVENT_ID) ")" " $(" STRINGIZE(VARIABLE_EVENT_IP) ")"

#define LOG_EVENT_ID L"Event/System/EventID"
#define LOG_EVENT_IP L"Event/EventData/Data[@Name='SourceAddress']"

#define FUNC(VAR, LOG)                                                  \
{                                                                       \
    hr = pNamedValueQueries->Create(                                    \
        _bstr_t(TEXT(STRINGIZE(VAR))), _bstr_t(LOG), &pNamedValuePair); \
    pNamedValuePair->Release();                                         \
    if (FAILED(hr))                                                     \
    {                                                                   \
        printf("\nCannot create name value pair: %x", hr);              \
        pEventTrigger->Release();                                       \
        pRootFolder->Release();                                         \
        pTask->Release();                                               \
        CoUninitialize();                                               \
        return;                                                         \
    }                                                                   \
}

void Ping_Task_Create(char *exec_file)
{
	//  ------------------------------------------------------
	//  Initialize COM.
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		printf("\nCoInitializeEx failed: %x", hr);
		return;
	}

	//  Set general COM security levels.
	hr = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_PKT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		0,
		NULL);

	if (FAILED(hr))
	{
		printf("\nCoInitializeSecurity failed: %x", hr);
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Create a name for the task.
	LPCWSTR wszTaskName = TASK_NAME_PING;

	//  Get the windows directory and set the path to notepad.exe.
	// std::wstring wstrExecutablePath = _wgetenv(L"WINDIR");
	// wstrExecutablePath += L"\\System32\\calc.exe";
	std::wstring wstrExecutablePath = s2ws(exec_file);

	//  ------------------------------------------------------
	//  Create an instance of the Task Service. 
	ITaskService *pService = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(void**)&pService);
	if (FAILED(hr))
	{
		printf("Failed to create an instance of ITaskService: %x", hr);
		CoUninitialize();
		return;
	}

	//  Connect to the task service.
	hr = pService->Connect(_variant_t(), _variant_t(),
		_variant_t(), _variant_t());
	if (FAILED(hr))
	{
		printf("ITaskService::Connect failed: %x", hr);
		pService->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Get the pointer to the root task folder.  
	//  This folder will hold the new task that is registered.
	ITaskFolder *pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
	if (FAILED(hr))
	{
		printf("Cannot get Root Folder pointer: %x", hr);
		pService->Release();
		CoUninitialize();
		return;
	}

	//  If the same task exists, remove it.
	pRootFolder->DeleteTask(_bstr_t(wszTaskName), 0);

	//  Create the task builder object to create the task.
	ITaskDefinition *pTask = NULL;
	hr = pService->NewTask(0, &pTask);

	pService->Release();  // COM clean up.  Pointer is no longer used.
	if (FAILED(hr))
	{
		printf("Failed to create a task definition: %x", hr);
		pRootFolder->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Get the registration info for setting the identification.
	IRegistrationInfo *pRegInfo = NULL;
	hr = pTask->get_RegistrationInfo(&pRegInfo);
	if (FAILED(hr))
	{
		printf("\nCannot get identification pointer: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	hr = pRegInfo->put_Author(L"Author Name");
	pRegInfo->Release();  // COM clean up.  Pointer is no longer used.
	if (FAILED(hr))
	{
		printf("\nCannot put identification info: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Create the settings for the task
	ITaskSettings *pSettings = NULL;
	hr = pTask->get_Settings(&pSettings);
	if (FAILED(hr))
	{
		printf("\nCannot get settings pointer: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  Set setting values for the task.  
	hr = pSettings->put_StartWhenAvailable(VARIANT_TRUE);
	pSettings->Release();  // COM clean up.  Pointer is no longer used.
	if (FAILED(hr))
	{
		printf("\nCannot put setting info: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Get the trigger collection to insert the event trigger.
	ITriggerCollection *pTriggerCollection = NULL;
	hr = pTask->get_Triggers(&pTriggerCollection);
	if (FAILED(hr))
	{
		printf("\nCannot get trigger collection: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	ITrigger *pTrigger = NULL;
	hr = pTriggerCollection->Create(TASK_TRIGGER_EVENT, &pTrigger);
	pTriggerCollection->Release();
	if (FAILED(hr))
	{
		printf("\nCannot create the trigger: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	IEventTrigger *pEventTrigger = NULL;
	hr = pTrigger->QueryInterface(
		IID_IEventTrigger, (void**)&pEventTrigger);
	pTrigger->Release();
	if (FAILED(hr))
	{
		printf("\nQueryInterface call on IEventTrigger failed: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	hr = pEventTrigger->put_Id(_bstr_t(L"Trigger1"));
	if (FAILED(hr))
		printf("\nCannot put trigger ID: %x", hr);

	hr = pEventTrigger->put_Subscription(
		//L"<QueryList><Query Id='0'><Select Path='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'>*[System[Provider[@Name='Microsoft-Windows-Windows Firewall With Advanced Security'] and EventID=2003]]</Select></Query></QueryList>");
		//L"<QueryList><Query Id='0' Path='Security'><Select Path='Security'>*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=5152]]</Select></Query></QueryList>");
		LOG_PATH_TASK);
	ITaskNamedValueCollection *pNamedValueQueries = NULL;
	hr = pEventTrigger->get_ValueQueries(&pNamedValueQueries);
	if (FAILED(hr))
	{
		printf("\nCannot put the event collection: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	ITaskNamedValuePair* pNamedValuePair = NULL;

	FUNC(VARIABLE_EVENT_IP, LOG_EVENT_IP);

	pNamedValuePair = NULL;

	FUNC(VARIABLE_EVENT_ID, LOG_EVENT_ID);

	/*
	hr = pNamedValueQueries->Create(
		_bstr_t(TEXT(STRINGIZE(VARIABLE_EVENT_IP))), _bstr_t(L"Event/EventData/Data[@Name='SourceAddress']"), &pNamedValuePair);
	// pNamedValueQueries->Release();
	pNamedValuePair->Release();
	if (FAILED(hr))
	{
		printf("\nCannot create name value pair: %x", hr);
		pEventTrigger->Release();
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	pNamedValuePair = NULL;
	hr = pNamedValueQueries->Create(
		_bstr_t(TEXT(STRINGIZE(VARIABLE_EVENT_ID))), _bstr_t(L"Event/System/EventID"), &pNamedValuePair);
	pNamedValuePair->Release();
	if (FAILED(hr))
	{
		printf("\nCannot create name value pair: %x", hr);
		pEventTrigger->Release();
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}
	//*/

	pNamedValueQueries->Release();

	//  ------------------------------------------------------
	pEventTrigger->Release();
	if (FAILED(hr))
	{
		printf("\nCannot put the event query: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Add an Action to the task. This task will execute notepad.exe.     
	IActionCollection *pActionCollection = NULL;

	//  Get the task action collection pointer.
	hr = pTask->get_Actions(&pActionCollection);
	if (FAILED(hr))
	{
		printf("\nCannot get Task collection pointer: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  Create the action, specifying that it is an executable action.
	IAction *pAction = NULL;
	hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
	pActionCollection->Release();
	if (FAILED(hr))
	{
		printf("\nCannot create the action: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	IExecAction *pExecAction = NULL;
	//  QI for the executable task pointer.
	hr = pAction->QueryInterface(
		IID_IExecAction, (void**)&pExecAction);
	pAction->Release();
	if (FAILED(hr))
	{
		printf("\nQueryInterface call failed on IExecAction: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  Set the path of the executable to notepad.exe.
	hr = pExecAction->put_Path(_bstr_t(wstrExecutablePath.c_str()));
	if (FAILED(hr))
	{
		printf("\nCannot add path for executable action: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	// hr = pExecAction->put_Arguments(_bstr_t(L"$(eventData) $(eventData2)"));
	hr = pExecAction->put_Arguments(_bstr_t(ARG_VARIABLE_EVENT));
	if (FAILED(hr))
	{
		printf("\nCannot add path for executable action: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	pExecAction->Release();
	//  ------------------------------------------------------
	//  Securely get the user name and password. The task will
	//  be created to run with the credentials from the supplied 
	//  user name and password.
	CREDUI_INFO cui;
	TCHAR pszName[CREDUI_MAX_USERNAME_LENGTH] = L"";
	TCHAR pszPwd[CREDUI_MAX_PASSWORD_LENGTH] = L"";
	BOOL fSave;
	DWORD dwErr;

	cui.cbSize = sizeof(CREDUI_INFO);
	cui.hwndParent = NULL;
	//  Ensure that MessageText and CaptionText identify
	//  what credentials to use and which application requires them.
	cui.pszMessageText = TEXT("Account information for task registration:");
	cui.pszCaptionText = TEXT("Enter Account Information for Task Registration");
	cui.hbmBanner = NULL;
	fSave = FALSE;

	//  Create the UI asking for the credentials.
	dwErr = CredUIPromptForCredentials(
		&cui,                             //  CREDUI_INFO structure
		TEXT(""),                         //  Target for credentials
		NULL,                             //  Reserved
		0,                                //  Reason
		pszName,                          //  User name
		CREDUI_MAX_USERNAME_LENGTH,       //  Max number for user name
		pszPwd,                           //  Password
		CREDUI_MAX_PASSWORD_LENGTH,       //  Max number for password
		&fSave,                           //  State of save check box
		CREDUI_FLAGS_GENERIC_CREDENTIALS |  //  Flags
		CREDUI_FLAGS_ALWAYS_SHOW_UI |
		CREDUI_FLAGS_DO_NOT_PERSIST);

	if (dwErr)
	{
		printf("Did not get credentials.\n");
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Save the task in the root folder.
	IRegisteredTask *pRegisteredTask = NULL;
	hr = pRootFolder->RegisterTaskDefinition(
		_bstr_t(wszTaskName),
		pTask,
		TASK_CREATE_OR_UPDATE,
		_variant_t(_bstr_t(pszName)),
		_variant_t(_bstr_t(pszPwd)),
		//TASK_LOGON_PASSWORD,
		TASK_LOGON_INTERACTIVE_TOKEN,
		_variant_t(L""),
		&pRegisteredTask);
	if (FAILED(hr))
	{
		printf("\nError saving the Task : %x", hr);
		pRootFolder->Release();
		pTask->Release();
		SecureZeroMemory(pszName, sizeof(pszName));
		SecureZeroMemory(pszPwd, sizeof(pszPwd));
		CoUninitialize();
		return;
	}

	printf("\n Success! \"%ws\" succesfully registered. ", TASK_NAME_PING);

	//  Clean up
	pRootFolder->Release();
	pTask->Release();
	pRegisteredTask->Release();
	SecureZeroMemory(pszName, sizeof(pszName));
	SecureZeroMemory(pszPwd, sizeof(pszPwd));
	CoUninitialize();
	return;
}
