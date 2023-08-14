#pragma once
#include <openssl/ssl.h>
#include <openssl/bio.h>

namespace secure_proxy {

	class Client {
	public:
		Client() : ssl_(nullptr), input_(nullptr), output_(nullptr) {};
		Client(const Client&) = delete;
		Client(const Client&&) = delete;

		Client& operator=(const Client&) = delete;
		Client& operator=(const Client&&) = delete;

		~Client();
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
		//
		bool CreateBIO();

		// ������� ������, ���������� ��� BIO
		void ResetBIO();

		// ������� ������, ���������� ��� SSL
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
