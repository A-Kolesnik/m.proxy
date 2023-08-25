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
	* @brief Загружает неизменяемые для всех соединений компоненты.
	* @retval true  Загрузка выполнена успешно.
	* @retval false При загрузке произошли критические ошибки.
	*/
	bool Init();

	/*!
	* @brief Освобождает память, выделенную для всех неизменяемых компонентов модуля.
	*	Nothing.
	*/
	void Reset();

	namespace init_tools {

		/*
		* @brief Создает пару ключей сервера для создания сертификата.
		* @retval Ключи созданы успешно.
		* @retval При создании ключей произошла критическая ошибка.
		*/
		bool GenerateServerKeys();

		/*!
		* @brief Создает шаблон для запроса на выдачу сертификата CSR.
		* @retval true  Шаблон запроса успешно создан.
		* @retval false При создании шаблона произшла критическая ошибка.
		*/
		bool GenerateCSRTemplate();

		/*!
		* @brief Загружет необходимые компоненты коневого центра сертификации.
		* @retval true  Загрузка компонентов выполнена успешно
		* @retval false При загрузке компонентов произошла критическая ошибка
		*/
		bool LoadCAKeyData();
		
		/*!
		* @brief Формирует контексты для клиентской и серверной части Proxy
		* @retval true  Контексты сформированы успешно
		* @retval false При формировании одного из контекстов произошла критическая ошибка
		*/
		bool LoadCtx();
	}

	namespace reset_tools {
		/*!
		* @brief Освобождает память, выделенную для пары ключей сервера.
		*	Nothing.
		*/
		void ResetServerKeys();

		/*!
		* @brief Освобождает память, выделенную для сертификата и приватного ключа CA.
		*	Nothing.
		*/
		void ResetCA();

		/*!
		* @brief Освобождение памяти, выдлеленной для шаблона запроса CSR.
		*	Nothing.
		*/
		void ResetCSR();

		/*!
		* @brief Освобождение памяти, выделенной для контекстов клиента и сервера.
		*	Nothing.
		*/
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
