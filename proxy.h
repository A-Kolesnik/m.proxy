// Описывает: 
// 1. Функция инициализации части модуля, выполняющей операции TLS-соединения.
// 2. Функция сброса состояния данной части модуля (освобождение памяти)
// 3. Сущность Proxy, выступающая в роли сервера в локальной сети и в роли клиента в глобальной компьютерной сети.

#pragma once

#include <string>
#include <memory.h>
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
	// 
	// 
	// 
	// 
	// Заметки для разработки:
	//	- интерфейс должен поддерживать возможность контроля наличия данных для передачи клиенту/серверу
	//	- когда пользователь локальной сети инициирует создание TLS соединения, серверная часть Proxy
	//	  обрабатывает запрос пользователя ClientHello и отвечает соответствующим сообщением (со всеми 
	//	  атрибутами, в том числе включая сертификат). Ответ на следующее сообщение для установления 
	//	  соединения от пользователя LAN будет сформирован после того, как клиентская часть Proxy установит
	//    соединение с сервером в Интернете. Необработанное сообщение клиента будет храниться в BIO.
	//	  Для этого и нужен флаг, который будет указывать на то, есть ли данные для отправки клиенту/серверу.
	// API OpenSSL для реализации:
	//	1. SSL_in_before(): 1 - Handshake не был инициирован / 0 - Handshake был инициирован
	//  2. 
	// 
	class Proxy {
	public:
		Proxy() {};
		Proxy(const Proxy&) = delete;
		Proxy(const Proxy&&) = delete;

		Proxy& operator=(const Proxy&) = delete;
		Proxy& operator=(const Proxy&&) = delete;

		// Выполняет загрузку необходимых для поддержания соединения
		// сущностей: client/server
		// 

		bool Load();

		//
		bool ProcessLANClientMessage(unsigned char*, int);

		//
		bool ProcessWANServerMessage(unsigned char*, int);

		// Temp
		void Process(unsigned char*&, size_t&);
		//
		Server server_;
		Client client_;

	private:
		//
		bool EstablishLANConnection();
		bool EstablishWANConnection();

		bool PerformLANHandshake();
		bool PerformWANHandshake();

		void ResetBIOBuffer(BIO*);
		
		/*!
		* @brief Устанавливает расширение SNI в клиентской части Proxy
		* 
		* Значение для расширения извлекается из объекта SSL серверной части Proxy,
		* где устанавливается после обработки сообщения ClientHello. Если в сообщении
		* от клиента будет отсутствовать расширение SNI, операция установления соединения
		* будет прервана.
		* 
		* @return 
		*/
		bool SetServerName();

		/*!
		* @brief Обработка данных приложения
		* 
		* В процессе обработки выполняется шифрование/дешифрование данных,
		* обмен полученными данными между клиентской и серверной частью модуля.
		*/
		bool ProcessApplicationData(unsigned char*, int, bool);
		
		/*!
		* @brief Выполняет дешифрование сообщения
		*/
		bool DecryptData(share::Endpoint*,unsigned char*&, int&);

		/*!
		* @brief Выполняет шифрование данных. Результат транслируется в BIO output
		* 
		*/
		bool EncryptData(share::Endpoint*, unsigned char*, int);
	};
}
