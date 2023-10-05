/*!
* @file
* @brief Описывает вспомогательные классы и функции для работы TLS-части программного модуля.
*/

#pragma once

#include <memory>
#include <iostream>
#include <filesystem>

namespace fs = std::filesystem;

namespace tools {

	/*!
	* @brief Закрывает поток
	* @details 
	* Реализация в отдельном классе выполнена с целью
	* использования smart pointers для работы с файлами
	*/
	class FileCloser {
	public:
		void operator()(FILE* fd) const { fclose(fd); }
	};

	/*!
	* @brief Открывает файл.
	* 
	* @param[in] file_path Путь к файлу.
	* @param[in] mode      Режим открытия файла.
	* 
	* @return Поток в виде Smart Pointer.
	*/
	std::unique_ptr<FILE, FileCloser> OpenFile(const fs::path&, std::string);

	/*!
	* @brief Увеличивает размер участка памяти
	* 
	* @param[in,out] buf          Указатель на начало участка памяти, который необходимо расширить
	* @param[in]     update_size  Размер участка памяти, до которого необходимо расширить 
	* 
	* @retval true  Операция выполнена успешно.
	* @retval false Произошла критическая ошибка.
	*/
	template<typename T>
	bool ExpandBuffer(T*& buf, int update_size) {
		buf = (T*)std::realloc(buf, update_size);
		if (!buf) { return false; }

		return true;
	}

	/*!
	* @brief Выделяет память.
	* 
	* @param[in,out] mem_location Ссылка на указатель на выделенный участок памяти.
	* @param[in]     size         Запрашиваемый размер участка памяти.
	* 
	* @retval true  Память выделена успешно.
	* @retval false Произошла критическая ошибка.
	*/
	template<typename T>
	bool AllocateMemory(T*& mem_location, int size) {
		mem_location = (T*)malloc(size);
		if (!mem_location) { return false; }

		return true;
	}

	/*!
	* @brief Освобождает выделеную память.
	* 
	* @param[in] mem_location Указатель на участок памяти.
	* @param[in] is_array     Выделена память под массив или нет.
	*	Nothing.
	*/
	template<typename T>
	void ClearMemory(T* mem_location, bool is_array) {
		if (is_array) { delete[] mem_location; }
		else { delete mem_location; }
	}
}
