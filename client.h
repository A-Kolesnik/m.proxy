#pragma once
#include <openssl/ssl.h>
#include <openssl/bio.h>

namespace secure_proxy {

	class Client {
	public:
		Client() : ssl_(nullptr), input_(nullptr), output_(nullptr) {};
		Client(const Client&) = delete;
		Client(const Client&&) = delete;

		Client& operator=(const Client&) = delete;
		Client& operator=(const Client&&) = delete;

		~Client();
		// Создает сущности для организации и поддержания соединения:
		// 1. Экземпляр SSL - описывает параметры соединения(версия протокола, криптографичекие наборы и т.д.)
		// Параметры для создания извлекаются из контекста.
		// 2. Создание базовых потоков ввода/вывода BIO
		// 3. Связывание экземпляра SSL с BIO
		//
		bool Load();
	private:
		// Создает и конфигурирует SSL
		bool CreateSSL();

		// Создает и конфигурирует BIO.
		// Конфигурация заключается в установке неблокирующего режима работы.
		// 
		//
		//
		bool CreateBIO();

		// Удаляет память, выделенную для BIO
		void ResetBIO();

		// Удаляет память, выделенную для SSL
		void ResetSSL();
		
		SSL* ssl_;

		// Используется 2 объекта BIO, поскольку канал BIO является пайплайном.
		// Соответственно, точка входа - input, выхода - output.
		// Также возможно навешивать фильтры.
		//
		BIO* input_;
		BIO* output_;
	};
}
