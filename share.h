// Описывает Singleton классы
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
		// Callback-функция для обработки сообщения ClientHello
		int ProcessClientHello(SSL*, int*, void*);
		bool IsExistsSNI(SSL*, const unsigned char**, size_t*);
		int GetLenExtensionValue(const unsigned char*&);
		bool CheckLenExtension(const unsigned char*&, size_t*);
		bool CheckTypeExtensionSNI(const unsigned char*&);
		std::string GetSNI(const unsigned char*&);
	}

	// Singleton-класс создает ключи сервера. 
	// 
	// Реализация обоснована тем, что для каждого пользовательского
	// соединения необходимо выполнять генерацию запроса к CA на выдачу
	// сертификата. Для этого необходимо наличие ключей сервера. 
	// Генерация ключей является временнозатратной операций. Поэтому
	// для всех соелинений будет использована одна пара ключей.
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

	// Singleton-класс создает шаблон запроса на выдачу сертификата к CA.
	// 
	// Т.к. модуль работает в однопоточном режиме, для каждого нового соединения
	// можно использовать один объект CSR, изменяя только одно поле - это CN (domain name).
	// Остальные поля остаются неизменными.
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

	// Singleton-класс создает контекст, на базе которого будут созданы экземпляры SSL.
	// 
	// API OpenSSL позволяет указывать сертификат, используемый сервером двумя способами:
	// 1. В контексте перед созданием экземпляра сессии SSL
	// 2. Непосредственно в экземпляре SSL
	// 
	// Реализация данного модуля предполагает использование способа 2. Это обусловлено тем, что
	// установка используемого сертификата выполняется после его генерации. Для генерации необходимо
	// расширение SNI, содержащееся в сообщении ClientHello. Обработка ClientHello выполняется в функции 
	// обратного вызова, которая вызывается SSL_do_handshake. А перед вызовом SSL_do_handshake объект SSL
	// должен быть создан. А т.к. объект SSL создается на базе контекста, то изменение параметров сессии, 
	// в частности, установка используемого сертификата, выполняется непосредственно, в экземпляре сессии.
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
	
	// Singleton-класс описывает центр сертификации.
	// Предполагается, что сертификат и приватный ключ созданные ранее и будут загружены из файла
	// 
	class RootCA {
	public:
		RootCA(const RootCA&) = delete;
		RootCA& operator=(const RootCA&) = delete;

		static RootCA* Get();

		// Выполняет создание сертификата на основе Domain Name
		X509* IssueCertificate(const std::string&);
		X509* GetCertificate() { return certificate_; }
		X509_NAME* GetIssuerName() { return issuer_name_; }
		EVP_PKEY* GetPrivateKey() { return private_key_; }

	protected:
		RootCA();
	private:
		// Выполняет загрузку файла в PEM формате
		template<typename T>
		T LoadPem(const fs::path&, T(*load_function)(FILE*, T*, pem_password_cb*, void*));

		// Генерирует серийный номер для сертификата
		unsigned char* GenerateSerialNumber();

		// Заменяет поле Domain Name в  CSR
		bool ReplaceCSRDomainName(X509_REQ*, const std::string&);
		bool SetSerialNumber(ASN1_STRING*, unsigned char*, int);
		bool SetExpirationDate(X509*);

		// Устанавливает дополнительное поле SubjectAltName в сертификат.
		// Это необходимо, поскольку некоторые браузеры не пропускаю сертификаты без этого поля.
		// Поле содержит альтернатывные доменные именв
		// 
		bool SetSubjectAltName(X509*, const std::string&);

		// Подписывает сертификат
		bool Sign(X509*);
		X509* certificate_;
		X509_NAME* issuer_name_;
		EVP_PKEY* private_key_;
	};
}