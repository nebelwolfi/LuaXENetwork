#pragma once

#include <chrono>

namespace CTime {
	std::chrono::steady_clock::time_point Now();

	int Diff(std::chrono::steady_clock::time_point Start, std::chrono::steady_clock::time_point Now = std::chrono::steady_clock::now());
}