// Описывает: 
// 1. Функция инициализации части модуля, выполняющей операции TLS-соединения.
// 2. Функция сброса состояния данной части модуля (освобождение памяти)
// 3. Сущность Proxy, выступающая в роли сервера в локальной сети и в роли клиента в глобальной компьютерной сети.

#pragma once

#include <string>
#include "client.h"
#include "server.h"
#include "config.h"
#include "share.h"

namespace secure_proxy {
	
	// Загружает неизменяемые для всех соединений сущности:
	// 1. Пара ключей сервера(public/private)
	// 2. Запрос на выпуск сертификата CSR. Фактически, в 
	// запросе изменяется одно поле - это Domain Name, которое
	// передается в расширении сообщения ClientHello SNI (Server Name Indicator)
	// 3. Контекст сервера
	// 
	// !!! Список будет продолжен сущностями для роли-клиент.
	// 
	// При успешном выполнении всех операций, функция возвращает true,
	// в противном случае, false. 
	// 
	// !!! Надо обсудить, как в рамках всего модуля обрабатывать ошибки из этой части.
	// 
	// Если произошла ошибка при выполнении одной из операций загрузки,
	// память, выделенная на предыдущих шагах, очищается.
	// После успешного выполнения функции, для очистки памяти необходимо вызвать 
	// функцию Reset.
	// 
	// Пример использования:
	// 
	// 1-> if(!secure_proxy::Init()) { exit(1); };
	// 2-> secure_proxy::Reset();
	//
	bool Init();
	void Reset();

	namespace init_tools {
		bool GenerateServerKeys();
		bool GenerateCSRTemplate();
		bool LoadCAKeyData();
		bool LoadCtx();
	}

	namespace reset_tools {
		void ResetServerKeys();
		void ResetCA();
		void ResetCSR();
		void ResetCTX();
	}

	// Реализация не окончена
	// 
	// Выполняет поддержку отдельного соединения.
	// Экземпляр класса создается для каждого нового соединения.
	// Класс НЕ поддерживает многопоточное использование.
	//
	// Пример создания экземпляра класса:
	// 
	// 1-> secure_proxy::Proxy proxy{};
	// 2-> if(!proxy.Load()){ exit(1); }
	// 
	class Proxy {
	public:
		Proxy(){};
		Proxy(const Proxy&) = delete;
		Proxy(const Proxy&&) = delete;

		Proxy& operator=(const Proxy&) = delete;
		Proxy& operator=(const Proxy&&) = delete;

		// Выполняет загрузку необходимых для поддержания соединения
		// сущностей: client/server
		// 
		//
		bool Load();

		Server server_;
		Client client_;
	};
}
