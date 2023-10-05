/*!
* @file
* @brief ќписывает класс Server
*/

#pragma once

#include <openssl/rsa.h>
#include <openssl/ssl.h>


#include <memory>

#include "config.h"
#include "share.h"

namespace secure_proxy {

	/*!
	* @brief ќписывает интерфейс дл¤ работы серверной части Proxy.
	*/
	class Server : public share::Endpoint {
	public:
		using Endpoint::Endpoint;

		Server(const Server&) = delete;
		Server(const Server&&) = delete;

		Server& operator=(const Server&) = delete;
		Server& operator=(const Server&&) = delete;

		/*!
		* @brief ¬ыполн¤ет очередной шаг процедуры установлени¤ соединени¤.
		*
		* @retval true  ќпераци¤ выполнена успешно.
		* @retval false ѕроизошла критическа¤ ошибка.
		*/
		bool PerformHandshake() override;

	private:
		/*!
		* @brief —оздает экземпл¤р SSL и выполн¤ет его конфигурацию
		*
		* @retval true  Ёкземпл¤р создан и сконфигурирован успешно.
		* @retval false ѕроизошла критическа¤ ошибка при создании или конфигурации экземпл¤ра SSL.
		*/
		bool CreateSSL() override;
	};
}
