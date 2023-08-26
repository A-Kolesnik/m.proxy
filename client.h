/*!
* @file
* @brief Описывает класс Client
*/
#pragma once
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "share.h"

namespace secure_proxy {

	/*!
	* @brief Описывает интерфейс для работы клиентской части Proxy.
	*/
	class Client : public share::Endpoint {
	public:
		using Endpoint::Endpoint;

		Client(const Client&) = delete;
		Client(const Client&&) = delete;

		Client& operator=(const Client&) = delete;
		Client& operator=(const Client&&) = delete;

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
