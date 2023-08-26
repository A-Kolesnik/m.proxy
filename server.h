/*!
* @file
* @brief Описывает класс Server
*/

#pragma once

#include <openssl/rsa.h>
#include <openssl/ssl.h>


#include <memory>

#include "config.h"
#include "share.h"

namespace secure_proxy {

	/*!
	* @brief Описывает интерфейс для работы серверной части Proxy.
	*/
	class Server : public share::Endpoint {
	public:
		using Endpoint::Endpoint;

		Server(const Server&) = delete;
		Server(const Server&&) = delete;

		Server& operator=(const Server&) = delete;
		Server& operator=(const Server&&) = delete;

		/*!
		* @brief Выполняет очередной шаг процедуры установления соединения.
		*
		* @retval true  Операция выполнена успешно.
		* @retval false Произошла критическая ошибка.
		*/
		bool PerformHandshake() override;

	private:
		/*!
		* @brief Создает экземпляр SSL и выполняет его конфигурацию
		*
		* @retval true  Экземпляр создан и сконфигурирован успешно.
		* @retval false Произошла критическая ошибка при создании или конфигурации экземпляра SSL.
		*/
		bool CreateSSL() override;
	};
}
