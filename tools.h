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
}
