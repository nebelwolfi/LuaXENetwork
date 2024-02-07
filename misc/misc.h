#pragma once

#ifndef MISC_H
#define MISC_H

#include <string>

std::wstring GetExeDirectoryW();
std::string GetExeDirectory();
std::wstring GetAndCreateCachePath(std::wstring Foldername = L"Cache");
bool file_exists(const std::string& name);
bool file_exists(const std::wstring& name);
bool file_copy(std::wstring& SourcePath, std::wstring& TargetPath);
std::string utf8_encode(const std::wstring &wstr);
std::wstring utf8_decode(const std::string &str);
std::string utf8_encode_lua(const std::wstring &wstr);
std::wstring utf8_decode_lua(const std::string &str);
#endif
