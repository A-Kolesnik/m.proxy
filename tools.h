// ��������� ��������������� ������ � ������� ��� ������ ������.
// ���� ������ ������ � �������
#pragma once
#include <memory>
#include <iostream>
#include <filesystem>

namespace fs = std::filesystem;

namespace tools {
	// ��������� �������� ������.
	// ����������� � ��������� ������ � ����� ������������� 
	// ��������� ����� ���������� ��� ������ � �������
	//
	class FileCloser {
	public:
		void operator()(FILE* fd) const { fclose(fd); }
	};

	std::unique_ptr<FILE, FileCloser> OpenFile(const fs::path&, std::string);
}
