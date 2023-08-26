#include "tools.h"

/*!
* @details
*/
std::unique_ptr<FILE, tools::FileCloser> tools::OpenFile(const fs::path& file_path, std::string mode) {
	return std::unique_ptr<FILE, FileCloser>(fopen(file_path.c_str(), mode.c_str()));
}