// ��������� �������� Server. ������� �����, ���� Proxy � �������� �������,
// �.�. ��������� Proxy � ��������� ����. ����� Server � Proxy -> ���������
// Server - �������� ���������� Proxy
// 
//

#pragma once

#include <openssl/rsa.h>
#include <openssl/ssl.h>


#include <memory>

#include "config.h"
#include "share.h"

namespace secure_proxy {

	class Server : public share::Endpoint {
	public:
		// ����������� ������������ �������� ������
		using Endpoint::Endpoint;

		Server(const Server&) = delete;
		Server(const Server&&) = delete;

		Server& operator=(const Server&) = delete;
		Server& operator=(const Server&&) = delete;

		bool PerformHandshake() override;
		// ��� �������� ������� ����� ������ ���������� �������� ������

	private:
		bool CreateSSL() override;
	};
}
