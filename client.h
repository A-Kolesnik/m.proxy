/*!
* @file
* @brief ��������� ����� Client
*/
#pragma once
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "share.h"

namespace secure_proxy {

	/*!
	* @brief ��������� ��������� ��� ������ ���������� ����� Proxy.
	*/
	class Client : public share::Endpoint {
	public:
		using Endpoint::Endpoint;

		Client(const Client&) = delete;
		Client(const Client&&) = delete;

		Client& operator=(const Client&) = delete;
		Client& operator=(const Client&&) = delete;

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
