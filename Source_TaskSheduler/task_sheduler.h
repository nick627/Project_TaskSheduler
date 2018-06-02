#pragma once

#define _CRT_SECURE_NO_WARNINGS

#define _WIN32_DCOM

#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <comdef.h>
#include <wincred.h>
//  Include the task header file.
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "credui.lib")


std::wstring s2ws(const std::string& str);


bool Delete_Task(std::wstring taskName);

// list_task_sheduler.cpp
extern int Get_Tasks_and_Statuses();

// create_task_sheduler.cpp
void Firewall_Defender_Task_Create(char *exec_file);

// ping_task_sheduler.cpp
void Ping_Task_Create(char *exec_file);
