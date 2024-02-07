#include "misc.h"
#include <Windows.h>
#include <iostream>
#include <filesystem>
#include <istream>
#include <fstream>
#include <codecvt>

std::string GetExeDirectory() {
	char buffer[MAX_PATH];
	int bytes = GetModuleFileNameA(NULL, buffer, MAX_PATH);
	if (bytes == 0)
		return std::string();
	else {
		std::string ws = buffer;
		std::string NormalStr = std::string(ws.begin(), ws.end());
		std::reverse(NormalStr.begin(), NormalStr.end());
		int FirstBackslash = NormalStr.find('\\') + 1;
		std::reverse(NormalStr.begin(), NormalStr.end());
		NormalStr = NormalStr.substr(0, NormalStr.length() - FirstBackslash);
		return NormalStr;
	}
}

std::wstring GetExeDirectoryW() {
    wchar_t buffer[MAX_PATH];
    int bytes = GetModuleFileNameW(NULL, buffer, MAX_PATH);
    if (bytes == 0)
        return std::wstring();
    else {
        std::wstring ws = buffer;
        std::wstring NormalStr = std::wstring(ws.begin(), ws.end());
        std::reverse(NormalStr.begin(), NormalStr.end());
        int FirstBackslash = NormalStr.find('\\') + 1;
        std::reverse(NormalStr.begin(), NormalStr.end());
        NormalStr = NormalStr.substr(0, NormalStr.length() - FirstBackslash);
        return NormalStr;
    }
}

// Convert a wide Unicode string to an UTF8 string
std::string utf8_encode(const std::wstring &wstr)
{
    if( wstr.empty() ) return {};
    int size_needed = WideCharToMultiByte(CP_ACP, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo( size_needed, 0 );
    WideCharToMultiByte                  (CP_ACP, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// Convert an UTF8 string to a wide Unicode String
std::wstring utf8_decode(const std::string &str)
{
    if( str.empty() ) return {};
    int size_needed = MultiByteToWideChar(CP_ACP, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo( size_needed, 0 );
    MultiByteToWideChar                  (CP_ACP, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

// Convert a wide Unicode string to an UTF8 string
std::string utf8_encode_lua(const std::wstring &wstr)
{
    if( wstr.empty() ) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo( size_needed, 0 );
    WideCharToMultiByte                  (CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// Convert an UTF8 string to a wide Unicode String
std::wstring utf8_decode_lua(const std::string &str)
{
    if( str.empty() ) return {};
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo( size_needed, 0 );
    MultiByteToWideChar                  (CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::wstring GetAndCreateCachePath(std::wstring FolderName) {
	std::wstring CachePath = GetExeDirectoryW() + L"\\cache";
	std::filesystem::create_directory(CachePath);
	CachePath += L"\\" + FolderName;
	std::filesystem::create_directory(CachePath);
	return CachePath;
}

bool file_exists(const std::string& name) {
	std::ifstream f(name.c_str());
	return f.good();
}

bool file_exists(const std::wstring& name) {
	std::ifstream f(name.c_str());
	return f.good();
}

bool file_copy(std::wstring& SourcePath, std::wstring& TargetPath) {
	std::string FileContents;
	try {
		std::ifstream InFile(SourcePath, std::ifstream::binary);
		if (!InFile.good()) {
			std::wcout << "Failed to Copy File: " << SourcePath << std::endl;
			return false;
		}
		else {
			InFile.seekg(0, InFile.end);
			long length = (long)InFile.tellg();
			InFile.seekg(0, InFile.beg);
			char * buffer = new char[length];
			InFile.read(buffer, length);
			FileContents.assign(buffer, length);
			InFile.close();
			delete[] buffer;
		}
	}
	catch (std::exception &e) {
		std::wcout << "Failed to Copy File: " << SourcePath << " Error: " << e.what() << std::endl;
		return false;
	}

	try {
		std::ofstream outfile(TargetPath, std::ofstream::binary);
		if (!outfile.good()) {
			std::wcout << "Failed to Copy File: " << TargetPath << std::endl;
			return false;
		}
		else {
			outfile.write(FileContents.c_str(), FileContents.size());
			outfile.close();
			return true;
		}
	}
	catch (std::exception &e) {
		std::wcout << "Failed to Copy File: " << SourcePath << " Error: " << e.what() << std::endl;
		return false;
	}
	return false;
}
