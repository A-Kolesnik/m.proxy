/*!
* @file
* @brief ќписывает класс Client
*/
#pragma once
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "share.h"

namespace secure_proxy {

	/*!
	* @brief ќписывает интерфейс дл¤ работы клиентской части Proxy.
	*/
	class Client : public share::Endpoint {
	public:
		using Endpoint::Endpoint;

		Client(const Client&) = delete;
		Client(const Client&&) = delete;

		Client& operator=(const Client&) = delete;
		Client& operator=(const Client&&) = delete;

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
