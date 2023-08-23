/*!
* @file
* @brief Описывает классы и функции поддержания и установления TLS-соединения
* 
* Файл содержит в себе описание следующих компонентов:
*  * Класс Proxy
*  * Функция загрузки данной части программного модуля
*  * Функция сброса данной части программного модуля
*/

#pragma once

#include <string>
#include <memory.h>
#include "client.h"
#include "server.h"
#include "config.h"
#include "share.h"

namespace secure_proxy {
	/*!
	* @brief
	*/
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

	/*!
	* @brief Поддерживает отдельное TLS-соединение
	* @details
	* Экземпляр класса создается для каждого нового соединения и выступает в качестве сервера в локальной сети  
	* и в качестве клиента во внешней. Обеспечивает обработку системных сообщений протокола, а также данных   
	* приложений в рамках соединения. Пример создания экземпляра класса:  
	* @code
	* secure_proxy::Proxy proxy{};
	* if(!proxy.Load()){ exit(1); }
	* @endcode
	*/
	class Proxy {
	public:
		Proxy() {};
		Proxy(const Proxy&) = delete;
		Proxy(const Proxy&&) = delete;

		Proxy& operator=(const Proxy&) = delete;
		Proxy& operator=(const Proxy&&) = delete;

		/*!
		* @brief Выполняет загрузку необходимых компонентов сервера и клиента
		* 
		* @retval true  Загрузка выполнена успешно
		* @retval false При загрузке возникли критические ошибки
		*/
		bool Load();

		/*!
		* @brief Обрабатывает сообщение клиента локальной сети
		* 
		* @param[in] message     Сообщение клиента
		* @param[in] message_len Размер сообщения
 		* 
		* @retval true  Обработка сообщения выполнена успешно
		* @retval false При обработке сообщения возникли критические ошибки
		*/
		bool ProcessLANClientMessage(unsigned char*, int);

		/*!
		* @brief Обрабатывает сообщение сервера внешней сети
		* 
		* @param[in] message     Сообщение сервера
		* @param[in] message_len Размер сообщения
 		* 
		* @retval true  Обработка сообщения выполнена успешно
		* @retval false При обработке сообщения возникли критические ошибки
		*/
		bool ProcessWANServerMessage(unsigned char*, int);

		Server server_;//!< Представляет класс в локальной сети
		Client client_;//!< Представляет класс во внешней сети

	private:
		/*!
		* @brief Устанавливает соединение клиента локальной сети с сервером Proxy
		* 
		* @retval true  Операция выполнена успешно
		* @retval false Операция не выполнена
		*/
		bool EstablishLANConnection();

		/*!
		* @brief Устанавливает соединение Proxy клиента с WAN сервером
		*
		* @retval true  Операция выполнена успешно
		* @retval false Операция не выполнена
		*/
		bool EstablishWANConnection();

		/*!
		* @brief Выполняет очередную операцию Handshake для серверной части Proxy
		* 
		* @retval true  Операция выполнена успешно
		* @retval false Операция не выполнена
		*/
		bool PerformLANHandshake();

		/*!
		* @brief Выполняет очередную операцию Handshake для клиентской части Proxy
		* 
		* @retval true  Операция выполнена успешно
		* @retval false Операция не выполнена
		*/
		bool PerformWANHandshake();

		/*!
		* @brief Сбрасывает состояние BIO.
		* 
		* @param[in,out] bio Объект BIO
		*	Nothing.
		*/
		void ResetBIOBuffer(BIO*);
		
		/*!
		* @brief Устанавливает расширение SNI в клиентской части Proxy.
		* 
		* @param[in] sni Доменное имя сервера, запрашиваемое клиентом
		* 
		* @retval true  Расширение добавлено успешно
		* @retval false Расширение не добавлено
		*/
		bool SetSNI(std::string);

		/*!
		* @brief Устанавливает ожидаемое имя сервера в возвращаемом сертификате в клиентской части Proxy.
		* 
		* @param[in] host_name Ожидаемое имя сервера
		* 
		* @retval true  Ожидаемое имя сервера установлено
		* @retval false Ожидаемое имя сервера не установлено
		*/
		bool SetExpectedHostName(std::string);

		/*!
		* @brief Выполняет конфигурирование зависимых от имени сервера параметров клиентской части Proxy.
		* 
		* @retval true  Конфигурирование выполнено успешно
		* @retval false Конфигурирование не выполнено
		*/
		bool ConfigureClientProxyGivenSNI();

		/*!
		* @brief Обрабатывает данные приложения.
		* 
		* @param[in] is_server   Маркер роли, в которой выступает Proxy(клиент/сервер)
		* 
		* @retval true  Обработка сообщения выполнена успешно
		* @retval false Требуется разрыв соединения из-за критической ошибки, либо по запросу одной из сторон.
		*/
		bool ProcessApplicationData(bool);
		
		/*!
		* @brief Расшифровывает сообщение.
		* 
		* @param[in]     role      Экземпляр Client/Server
		* @param[in,out] buf       Массив для записи расшифрованного сообщения
		* @param[in,out] decrypted Размер расшифрованного сообщения 
		* 
		* @retval true  Расшифрование выполнено успешно
		* @retval false При выполнении операции произошла критическая ошибка
		*/
		bool DecryptData(share::Endpoint*,unsigned char*&, int&);

		/*!
		* @brief Шифрует данные.
		* 
		* @param[in] role     Экземпляр Client/Server
		* @param[in] data     Данные для шифрования
		* @param[in] data_len Размер данных для шифрования
		* 
		* @retval true  Шифрование выполнено успешно
		* @retval false Шифрование не выполнено
		* 
		*/
		bool EncryptData(share::Endpoint*, unsigned char*, int);
	};
}
