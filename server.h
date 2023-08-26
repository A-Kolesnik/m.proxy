/*!
* @file
* @brief ��������� ����� Server
*/

#pragma once

#include <openssl/rsa.h>
#include <openssl/ssl.h>


#include <memory>

#include "config.h"
#include "share.h"

namespace secure_proxy {

	/*!
	* @brief ��������� ��������� ��� ������ ��������� ����� Proxy.
	*/
	class Server : public share::Endpoint {
	public:
		using Endpoint::Endpoint;

		Server(const Server&) = delete;
		Server(const Server&&) = delete;

		Server& operator=(const Server&) = delete;
		Server& operator=(const Server&&) = delete;

		/*!
		* @brief ��������� ��������� ��� ��������� ������������ ����������.
		*
		* @retval true  �������� ��������� �������.
		* @retval false ��������� ����������� ������.
		*/
		bool PerformHandshake() override;

	private:
		/*!
		* @brief ������� ��������� SSL � ��������� ��� ������������
		*
		* @retval true  ��������� ������ � ��������������� �������.
		* @retval false ��������� ����������� ������ ��� �������� ��� ������������ ���������� SSL.
		*/
		bool CreateSSL() override;
	};
}
