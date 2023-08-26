/*!
* @file
* @brief ��������� ��������������� ������ � ������� ��� ������ TLS-����� ������������ ������.
*/

#pragma once

#include <memory>
#include <iostream>
#include <filesystem>

namespace fs = std::filesystem;

namespace tools {

	/*!
	* @brief ��������� �����
	* @details 
	* ���������� � ��������� ������ ��������� � �����
	* ������������� smart pointers ��� ������ � �������
	*/
	class FileCloser {
	public:
		void operator()(FILE* fd) const { fclose(fd); }
	};

	/*!
	* @brief ��������� ����.
	* 
	* @param[in] file_path ���� � �����.
	* @param[in] mode      ����� �������� �����.
	* 
	* @return ����� � ���� Smart Pointer.
	*/
	std::unique_ptr<FILE, FileCloser> OpenFile(const fs::path&, std::string);

	/*!
	* @brief ����������� ������ ������� ������
	* 
	* @param[in,out] buf          ��������� �� ������ ������� ������, ������� ���������� ���������
	* @param[in]     update_size  ������ ������� ������, �� �������� ���������� ��������� 
	* 
	* @retval true  �������� ��������� �������.
	* @retval false ��������� ����������� ������.
	*/
	template<typename T>
	bool ExpandBuffer(T*& buf, int update_size) {
		buf = (T*)std::realloc(buf, update_size);
		if (!buf) { return false; }

		return true;
	}

	/*!
	* @brief �������� ������.
	* 
	* @param[in,out] mem_location ������ �� ��������� �� ���������� ������� ������.
	* @param[in]     size         ������������� ������ ������� ������.
	* 
	* @retval true  ������ �������� �������.
	* @retval false ��������� ����������� ������.
	*/
	template<typename T>
	bool AllocateMemory(T*& mem_location, int size) {
		mem_location = (T*)malloc(size);
		if (!mem_location) { return false; }

		return true;
	}

	/*!
	* @brief ����������� ��������� ������.
	* 
	* @param[in] mem_location ��������� �� ������� ������.
	* @param[in] is_array     �������� ������ ��� ������ ��� ���.
	*	Nothing.
	*/
	template<typename T>
	void ClearMemory(T* mem_location, bool is_array) {
		if (is_array) { delete[] mem_location; }
		else { delete mem_location; }
	}
}
