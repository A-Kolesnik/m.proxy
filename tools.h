// Описывает вспомогательные классы и функции для работы модуля.
// Пока только работа с файлами
#pragma once
#include <memory>
#include <iostream>
#include <filesystem>

namespace fs = std::filesystem;

namespace tools {
	// Выполняет закрытие потока.
	// Реализовано в отдельном классе с целью использования 
	// механизма умных указателей для работы с файлами
	//
	class FileCloser {
	public:
		void operator()(FILE* fd) const { fclose(fd); }
	};

	std::unique_ptr<FILE, FileCloser> OpenFile(const fs::path&, std::string);

	template<typename T>
	bool ExpandBuffer(T*& buf, int update_size) {
		buf = (T*)std::realloc(buf, update_size);
		if (!buf) { return false; }

		return true;
	}

	template<typename T>
	bool AllocateMemory(T*& mem_location, int size) {
		mem_location = (T*)malloc(size);
		if (!mem_location) { return false; }

		return true;
	}

	template<typename T>
	void ClearMemory(T* mem_location, bool is_array) {
		if (is_array) { delete[] mem_location; }
		else { delete mem_location; }
	}
}
