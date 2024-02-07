#include "Time.h"

namespace CTime {
	std::chrono::steady_clock::time_point Now() {
		 return std::chrono::steady_clock::now();
	}

	int Diff(std::chrono::steady_clock::time_point Start, std::chrono::steady_clock::time_point Now) {
		return std::chrono::duration_cast<std::chrono::milliseconds>(Now - Start).count();
	}
}