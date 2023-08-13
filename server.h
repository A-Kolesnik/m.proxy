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
	// ќписывет TLS-соединение в локальной сети
	// 
	// јналогично Proxy, создаетс€ отдельный экземпл€р дл€ каждого соединени€.
	// —оздание выполн€етс€ при создании экземпл€ра Proxy.
	//

	class Server {
	public:
		Server() : ssl_(nullptr), input_(nullptr), output_(nullptr) {};
		Server(const Server&) = delete;
		Server(const Server&&) = delete;

		Server& operator=(const Server&) = delete;
		Server& operator=(const Server&&) = delete;

		// —оздает сущности дл€ организации и поддержани€ соединени€:
		// 1. Ёкземпл€р SSL - описывает параметры соединени€(верси€ протокола, криптографичекие наборы и т.д.)
		// ѕараметры дл€ создани€ извлекаютс€ из контекста.
		// 2. —оздание базовых потоков ввода/вывода BIO
		// 3. —в€зывание экземпл€ра SSL с BIO
		//
		bool Load();
	private:
		// —оздает и конфигурирует SSL
		bool CreateSSL();

		// —оздает и конфигурирует BIO.
		//  онфигураци€ заключаетс€ в установке неблокирующего режима работы.
		// 
		//
		bool CreateBIO();

		SSL* ssl_;

		// »спользуетс€ 2 объекта BIO, поскольку канал BIO €вл€етс€ пайплайном.
		// —оответственно, точка входа - input, выхода - output.
		// “акже возможно навешивать фильтры.
		//
		BIO* input_;
		BIO* output_;
	};

}
