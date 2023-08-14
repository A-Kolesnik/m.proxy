// Описывает сущность Server. Имеется ввиду, роль Proxy в качестве сервера,
// т.е. поведение Proxy в локальной сети. Связь Server и Proxy -> Экземпляр
// Server - свойство экземпляра Proxy
// 
//

#pragma once

#include <openssl/rsa.h>
#include <openssl/ssl.h>


#include <memory>

#include "config.h"
#include "share.h"

namespace secure_proxy {
	// Описывет TLS-соединение в локальной сети
	// 
	// Аналогично Proxy, создается отдельный экземпляр для каждого соединения.
	// Создание выполняется при создании экземпляра Proxy.
	//

	class Server {
	public:
		Server() : ssl_(nullptr), input_(nullptr), output_(nullptr) {};
		Server(const Server&) = delete;
		Server(const Server&&) = delete;

		Server& operator=(const Server&) = delete;
		Server& operator=(const Server&&) = delete;

		~Server();
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
		bool CreateBIO();

		// Удаляет память, выделенную для BIO
		void ResetBIO();
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
