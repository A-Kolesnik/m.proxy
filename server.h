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

	class Server : public share::Endpoint {
	public:
		// Подключение конструктора базового класса
		using Endpoint::Endpoint;

		Server(const Server&) = delete;
		Server(const Server&&) = delete;

		Server& operator=(const Server&) = delete;
		Server& operator=(const Server&&) = delete;

		bool PerformHandshake() override;
		// При удалении объекта будет вызван деструктор базового класса

	private:
		bool CreateSSL() override;
	};
}
