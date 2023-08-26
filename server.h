// ќписывает сущность Server. »меетс€ ввиду, роль Proxy в качестве сервера,
// т.е. поведение Proxy в локальной сети. —в€зь Server и Proxy -> Ёкземпл€р
// Server - свойство экземпл€ра Proxy
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
		// ѕодключение конструктора базового класса
		using Endpoint::Endpoint;

		Server(const Server&) = delete;
		Server(const Server&&) = delete;

		Server& operator=(const Server&) = delete;
		Server& operator=(const Server&&) = delete;

		bool PerformHandshake() override;

	private:
		bool CreateSSL() override;
	};
}
