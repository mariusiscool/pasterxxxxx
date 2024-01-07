#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <vector>

#define code_rw CTL_CODE(FILE_DEVICE_UNKNOWN, 0x911, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_ba CTL_CODE(FILE_DEVICE_UNKNOWN, 0x912, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_cr3 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x913, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

uintptr_t image_base;

DWORD FindProcessId(const std::string& processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}

class driver_manager {

	INT32 process_id;

	struct info_t {
		UINT64 target_pid = 0;
		UINT64 target_address = 0x0;
		UINT64 buffer_address = 0x0;
		UINT64 size = 0;
		UINT64 return_size = 0;
		UINT64 GA = 0;
		UINT64 UP = 0;
	};

	typedef struct _rw {
		INT32 security;
		INT32 process_id;
		ULONGLONG address;
		ULONGLONG buffer;
		ULONGLONG size;
		BOOLEAN write;
	} rw, * prw;

	typedef struct _ba {
		INT32 security;
		INT32 process_id;
		ULONGLONG* address;
	} ba, * pba;

	typedef struct _cr3 {
		INT32 process_id;
	} cr3, * DTBStruct;

public:
	int pid;
	HANDLE m_driver_handle = nullptr;
	bool FindDriver() {
		m_driver_handle = CreateFileA(("\\\\.\\\{84754834701984709183745901837487098709879813798479879857091739847059173405}"), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (m_driver_handle == 0)
			return false;
		else
			return true;
		return true;
	}

	int m_width = 0;
	int m_height = 0;

	inline void GetCr3(int pid) {
		_cr3 arguments = { NULL };
		arguments.process_id = pid;

		DeviceIoControl(m_driver_handle, code_cr3, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
	}

	inline uintptr_t find_image(int pid1) {
		uintptr_t image_address = { NULL };
		_ba arguments = { NULL };

		arguments.process_id = pid1;
		arguments.address = (ULONGLONG*)&image_address;

		DeviceIoControl(m_driver_handle, code_ba, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);

		return image_address;
	}

	inline auto get_window(
		HWND hwnd) -> bool
	{
		if (!hwnd)
			return false;

		RECT rect;
		GetWindowRect(hwnd, &rect);
		m_width = rect.right - rect.left;
		m_height = rect.bottom - rect.top;

		return true;
	}

	inline void read_physical(PVOID address, PVOID buffer, DWORD size) {
		_rw arguments = { 0 };

		arguments.address = (ULONGLONG)address;
		arguments.buffer = (ULONGLONG)buffer;
		arguments.size = size;
		arguments.process_id = pid;
		arguments.write = FALSE;

		DeviceIoControl(m_driver_handle, code_rw, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
	}

	inline void write_physical(PVOID address, PVOID buffer, DWORD size) {
		_rw arguments = { 0 };

		arguments.address = (ULONGLONG)address;
		arguments.buffer = (ULONGLONG)buffer;
		arguments.size = size;
		arguments.process_id = pid;
		arguments.write = TRUE;

		DeviceIoControl(m_driver_handle, code_rw, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
	}
};

driver_manager gDriver;

template <typename T>
T read(uint64_t address) {
	T buffer{ };
	gDriver.read_physical((PVOID)address, &buffer, sizeof(T));
	return buffer;
}

template <typename T>
T write(uint64_t address, T buffer) {
	gDriver.write_physical((PVOID)address, &buffer, sizeof(T));
	return buffer;
}

int length(uintptr_t addr) { return read<int>(addr + 0x10); }

std::string readstring(uintptr_t addr) {
	try {
		static char buff[128] = { 0 };
		buff[length(addr)] = '\0';

		for (int i = 0; i < length(addr); ++i) {
			if (buff[i] < 128) {
				buff[i] = read<char>(addr + 0x14 + (i * 2));
			}
			else {
				buff[i] = '?';
				if (buff[i] >= 0xD800 && buff[i] <= 0xD8FF)
					i++;
			}
		}
		return std::string(&buff[0], &buff[length(addr)]);
	}
	catch (const std::exception& exc) {}
	return ("Error");
}

template <typename T>
T read_chain(const std::uintptr_t address, std::vector<uintptr_t> chain)
{
	uintptr_t cur_read = address;
	for (int i = 0; i < chain.size() - 1; ++i)
		cur_read = read<uintptr_t>(cur_read + chain[i]);
	return read<T>(cur_read + chain[chain.size() - 1]);
}

bool is_valid(const uint64_t adress)
{
	if (adress <= 0x400000 || adress == 0xCCCCCCCCCCCCCCCC || reinterpret_cast<void*>(adress) == nullptr || adress >
		0x7FFFFFFFFFFFFFFF) {
		return false;
	}
	return true;
}