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
	// �������� TLS-���������� � ��������� ����
	// 
	// ���������� Proxy, ��������� ��������� ��������� ��� ������� ����������.
	// �������� ����������� ��� �������� ���������� Proxy.
	//

	class Server {
	public:
		Server() : ssl_(nullptr), input_(nullptr), output_(nullptr) {};
		Server(const Server&) = delete;
		Server(const Server&&) = delete;

		Server& operator=(const Server&) = delete;
		Server& operator=(const Server&&) = delete;

		~Server();
		// ������� �������� ��� ����������� � ����������� ����������:
		// 1. ��������� SSL - ��������� ��������� ����������(������ ���������, ���������������� ������ � �.�.)
		// ��������� ��� �������� ����������� �� ���������.
		// 2. �������� ������� ������� �����/������ BIO
		// 3. ���������� ���������� SSL � BIO
		//
		bool Load();
	private:
		// ������� � ������������� SSL
		bool CreateSSL();

		// ������� � ������������� BIO.
		// ������������ ����������� � ��������� �������������� ������ ������.
		// 
		//
		bool CreateBIO();

		// ������� ������, ���������� ��� BIO
		void ResetBIO();
		void ResetSSL();

		SSL* ssl_;

		// ������������ 2 ������� BIO, ��������� ����� BIO �������� ����������.
		// ��������������, ����� ����� - input, ������ - output.
		// ����� �������� ���������� �������.
		//
		BIO* input_;
		BIO* output_;
	};

}
