// ��������� Singleton ������
//
#pragma once

#include <algorithm>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include "tools.h"

namespace fs = std::filesystem;

namespace share {
	namespace server_tools {
		// Callback-������� ��� ��������� ��������� ClientHello
		int ProcessClientHello(SSL*, int*, void*);
		bool IsExistsSNI(SSL*, const unsigned char**, size_t*);
		int GetLenExtensionValue(const unsigned char*&);
		bool CheckLenExtension(const unsigned char*&, size_t*);
		bool CheckTypeExtensionSNI(const unsigned char*&);
		std::string GetSNI(const unsigned char*&);
	}

	// Singleton-����� ������� ����� �������. 
	// 
	// ���������� ���������� ���, ��� ��� ������� �����������������
	// ���������� ���������� ��������� ��������� ������� � CA �� ������
	// �����������. ��� ����� ���������� ������� ������ �������. 
	// ��������� ������ �������� ����������������� ��������. �������
	// ��� ���� ���������� ����� ������������ ���� ���� ������.
	class ServerKeysMaker {

	public:
		ServerKeysMaker(const ServerKeysMaker&) = delete;
		ServerKeysMaker& operator=(const ServerKeysMaker&) = delete;

		static EVP_PKEY* Get(int);
	protected:
		explicit ServerKeysMaker(int);

	private:
		//static ServerKeysMaker* singleton_;
		EVP_PKEY* pair_keys_;
	};

	// Singleton-����� ������� ������ ������� �� ������ ����������� � CA.
	// 
	// �.�. ������ �������� � ������������ ������, ��� ������� ������ ����������
	// ����� ������������ ���� ������ CSR, ������� ������ ���� ���� - ��� CN (domain name).
	// ��������� ���� �������� �����������.
	class ServerCSRTemplateMaker {
	public:
		ServerCSRTemplateMaker(const ServerCSRTemplateMaker&) = delete;
		ServerCSRTemplateMaker& operator=(const ServerCSRTemplateMaker&) = delete;

		static X509_REQ* Get();
	protected:
		ServerCSRTemplateMaker();
	private:
		bool FillSubjectNameFields();
		bool AddTxtEntryToSubjectName(X509_NAME*,const std::string&, const std::string&);
		bool SetPublicKey();
		X509_REQ* csr_;
	};

	// Singleton-����� ������� ��������, �� ���� �������� ����� ������� ���������� SSL.
	// 
	// API OpenSSL ��������� ��������� ����������, ������������ �������� ����� ���������:
	// 1. � ��������� ����� ��������� ���������� ������ SSL
	// 2. ��������������� � ���������� SSL
	// 
	// ���������� ������� ������ ������������ ������������� ������� 2. ��� ����������� ���, ���
	// ��������� ������������� ����������� ����������� ����� ��� ���������. ��� ��������� ����������
	// ���������� SNI, ������������ � ��������� ClientHello. ��������� ClientHello ����������� � ������� 
	// ��������� ������, ������� ���������� SSL_do_handshake. � ����� ������� SSL_do_handshake ������ SSL
	// ������ ���� ������. � �.�. ������ SSL ��������� �� ���� ���������, �� ��������� ���������� ������, 
	// � ���������, ��������� ������������� �����������, ����������� ���������������, � ���������� ������.
	// 

	class ServerCTXMaker {
	public:
		ServerCTXMaker(const ServerCTXMaker&) = delete;
		ServerCTXMaker& operator=(const ServerCTXMaker&) = delete;

		static SSL_CTX* Get();
	protected:
		ServerCTXMaker();
	private:
		SSL_CTX* ctx_;
	};
	
	// Singleton-����� ��������� ����� ������������.
	// ��������������, ��� ���������� � ��������� ���� ��������� ����� � ����� ��������� �� �����
	// 
	class RootCA {
	public:
		RootCA(const RootCA&) = delete;
		RootCA& operator=(const RootCA&) = delete;

		static RootCA* Get();

		// ��������� �������� ����������� �� ������ Domain Name
		X509* IssueCertificate(const std::string&);
		X509* GetCertificate() { return certificate_; }
		X509_NAME* GetIssuerName() { return issuer_name_; }
		EVP_PKEY* GetPrivateKey() { return private_key_; }

	protected:
		RootCA();
	private:
		// ��������� �������� ����� � PEM �������
		template<typename T>
		T LoadPem(const fs::path&, T(*load_function)(FILE*, T*, pem_password_cb*, void*));

		// ���������� �������� ����� ��� �����������
		unsigned char* GenerateSerialNumber();

		// �������� ���� Domain Name �  CSR
		bool ReplaceCSRDomainName(X509_REQ*, const std::string&);
		bool SetSerialNumber(ASN1_STRING*, unsigned char*, int);
		bool SetExpirationDate(X509*);

		// ������������� �������������� ���� SubjectAltName � ����������.
		// ��� ����������, ��������� ��������� �������� �� ��������� ����������� ��� ����� ����.
		// ���� �������� �������������� �������� �����
		// 
		bool SetSubjectAltName(X509*, const std::string&);

		// ����������� ����������
		bool Sign(X509*);
		X509* certificate_;
		X509_NAME* issuer_name_;
		EVP_PKEY* private_key_;
	};
}