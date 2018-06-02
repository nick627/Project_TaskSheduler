#include "task_sheduler.h"

#include <string>
#include <tchar.h> 

#define HELP "*.exe [param]\n\
'-list'               -- List all tasks\n\
'-firdef'             -- Create notification of change in the firewall and defender\n\
'-ping'               -- Create notification about blocked packets\n\
'-delete \"name_task\"' -- delete task \"name_task\"\n"


std::wstring s2ws(const std::string& str)
{
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
	std::wstring wstrTo(size_needed, 0);
	MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
	return wstrTo;
}


bool Delete_Task(std::wstring taskName)
{
	if (FAILED(CoInitialize(nullptr))) {
		return false;
	}

	ITaskService *pITS;
	if (FAILED(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, (void **)&pITS))) {
		CoUninitialize();
		return false;
	}

	if (FAILED(pITS->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t()))) {
		pITS->Release();
		CoUninitialize();
		return false;
	}

	ITaskFolder *pITF;
	if (FAILED(pITS->GetFolder(_bstr_t(L"\\"), &pITF))) {
		pITS->Release();
		CoUninitialize();
		return false;
	}

	pITS->Release();

	if (FAILED(pITF->DeleteTask(_bstr_t(taskName.c_str()), 0))) {
		pITF->Release();
		CoUninitialize();
		return false;
	}

	pITF->Release();

	CoUninitialize();

	return true;
}


int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		printf(HELP);
		return -1;
	}

	for (int i = 0; i < argc; i++)
	{
		printf("%s\n", argv[i]);
	}

	char path[_MAX_PATH + 1];
	GetModuleFileNameA(0, path, sizeof(path) / sizeof(path[0]));
	int i = strlen(path);
	while (path[i] != _T('\\'))
		path[i--] = 0;
	strcat(path, "inf_event.txt");

	if (!strcmp(argv[1], "5152") || !strcmp(argv[1], "5007") || !strcmp(argv[1], "2003"))
	{
		std::string tmp("del ");
		tmp += path;
		//std::cout << tmp << std::endl << std::endl;
		//system("del C:\\Users\\Nick\\Downloads\\BSIT\\3\\test.txt");
		system(tmp.c_str());

		std::string tmp1;

		if (!strcmp(argv[1], "2003"))
		{
			tmp1 = "wevtutil qe \"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall\" /q:\"*[System[(EventID=";
		}
		else if (!strcmp(argv[1], "5007"))
		{
			tmp1 = "wevtutil qe \"Microsoft-Windows-Windows Defender/Operational\" /q:\"*[System[(EventID=";
		}
		else if (!strcmp(argv[1], "5152"))
		{
			tmp1 = "wevtutil qe Security /q:\"*[System[(EventID=";
		}

		tmp1 += argv[1];
		tmp1 += ")]]\" /f:text /rd:true /c:1 > ";
		tmp1 += path;
		//std::cout << tmp1 << std::endl << std::endl;
		//system("wevtutil qe Security /q:\"*[System[(EventID=5152)]]\" / f:text /rd:true /c:1 > C:\\Users\\Nick\\Downloads\\BSIT\\3\\test.txt");
		system(tmp1.c_str());

		//std::cout << path << std::endl << std::endl;
		//system("C:\\Users\\Nick\\Downloads\\BSIT\\3\\test.txt");
		system(path);

		//std::cout << tmp << std::endl << std::endl;
		//system("del C:\\Users\\Nick\\Downloads\\BSIT\\3\\test.txt");
		system(tmp.c_str());

		//system("pause");
		//getchar();
	}

	if (!strcmp(argv[1], "-list"))
	{
		Get_Tasks_and_Statuses();
	}
	else if (!strcmp(argv[1], "-firdef"))
	{
		Firewall_Defender_Task_Create(argv[0]);
	}
	else if (!strcmp(argv[1], "-ping"))
	{
		Ping_Task_Create(argv[0]);
	}
	else if (!strcmp(argv[1], "-delete"))
	{
		if (argc < 3)
		{
			printf("No identify delete task (e.g. *.exe -delete \"Event_FIREWALL_DEFENDER_Trigger_Task\")\n\
                                            \"Event_PING_Trigger_Task\"");
			return -1;
		}

		std::string s(argv[2]);
		std::wstring ws;
		ws.assign(s.begin(), s.end());
		//std::wcout << ws << std::endl;

		if (Delete_Task(ws.c_str()) == false)
		{
			wprintf(L"Error delete task '%ws'\n", ws.c_str());
		}
		else
		{
			wprintf(L"Delete task '%ws'\n", ws.c_str());
		}
	}
	else
	{
		printf(HELP);
	}

	return 0;
}
