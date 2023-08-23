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

	namespace ssl_status {
		enum code {
			SSL_STATUS_WANT_IO,
			SSL_STATUS_FAIL,
			SSL_STATUS_OK
		};

		enum read {
			READ_STATUS_LEFT_DATA,
			READ_STATUS_SUCCESS,
			READ_STATUS_RETRY,
			READ_STATUS_FAIL
		};
	}

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
	// 
	// При отправке запроса к стороннему CA, CSR подписывается приватным ключом сервера,
	// для проверки на подлинность. Поскольку CA реализован в модуле, данная проверка выполнять не будет.
	// Соответственно, и подписи тоже не будет
	//
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

	// Singleton-класс создает контекст сервера, на базе которого будут созданы экземпляры SSL.
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

	// Singleton-класс создает контекст клиента, на базе которого будут созданы экземпляры SSL.
	// 
	// В глобальной компьютерной сети Proxy выступает клиентом. Для всех соединений параметры будут неизменяемые.
	// Исключением является расширение SNI сообщения ClientHello. Поэтому для создания экземпляра
	// класса SSL для всех соединений будет использован один экземпляр контекста с предустановленными
	// параметрами. А расширение SNI будет добавлено в каждый отдельный экземпляр SSL.
	// 
	class ClientCTXMaker {
	public:
		ClientCTXMaker(const ClientCTXMaker&) = delete;
		ClientCTXMaker& operator=(const ClientCTXMaker&) = delete;

		static SSL_CTX* Get();
	protected:
		ClientCTXMaker();
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

	class Endpoint {
	public:
		Endpoint() : input_(nullptr), output_(nullptr), ssl_(nullptr), has_data_(false) {};
		~Endpoint();
		// Создает сущности для организации и поддержания соединения:
		// 1. Экземпляр SSL - описывает параметры соединения(версия протокола, криптографичекие наборы и т.д.)
		// Параметры для создания извлекаются из контекста.
		// 2. Создание базовых потоков ввода/вывода BIO
		// 3. Связывание экземпляра SSL с BIO
		//

		/*!
		* @brief 
		*/
		bool Load();
		virtual bool PerformHandshake() = 0;

		/*!
		* @brief Определяет, был ли инициирован Handshake
		*
		* @return true/false - Handshake инициирован/не инициирован соответственно
		*/
		bool IsHandshakeInit();

		enum ssl_status::code GetSSLStatus(int);

		/*!
		* @brief Проверяет BIO на наличие данных для чтения.
		*
		* Если BIO содержит данные для чтения, изменяется состояние флага has_data_
		*/
		void SetIsDataFlag(bool from_bio=true, bool value=true);

		bool SendToBIOChannel(unsigned char*, int);

		/*!
		* @brief Определяет состояние TLS-соединени
		*
		* @return true/false - соединение готово/не готово соответственно
		* для безопасной передачи данных
		*/
		bool IsTLSConnectionEstablished();

		/*!
		* @brief Определяет наличие данных для чтения и отправки клиенту/серверу
		* 
		* Маркером наличия данных является атрибут has_data_.
		* После выполнения любой операции с данными проверяется наличие 
		* результата обработки в выходном базовом потоке BIO. Если данные
		* для чтения есть, has_data_ устанавливается в true. Если данных нет, в false.
		* При считывании данных из выходного BIO, маркер has_data_ устанавливается
		* в false.
		* 
		* @return true/false - данные для отправки есть/нет соответственно
		*/
		bool HasReadData();
		

		/*!
		* @brief Чтение данных из BIO
		* 
		* Читает данные из BIO в буфер, который передает пользователь.
		* Количество прочитанных байт записывается в параметр, переданный
		* пользователем по ссылке. Ответственность за выделение и освобождение
		* памяти для буфера возлагается на пользователя. Если размер переданного
		* буфера меньше размера данных, которые необходимо прочитать, в буфер
		* будет записано количество байт, равное его размеру и возвращен код READ_STATUS_LEFT_DATA.
		* 
		* @param[out] buf      Область памяти, куда будут записаны прочитанные данные
		* @param[in]  buf_size Размер области памяти
		* @param[out] readed   Количество записанных байт
		* 
		* @return enum ssl_status::read
		* 1. READ_STATUS_LEFT_DATA - BIO содержит еще данные для чтения.
		* Переход в это состояние возможен в случае, если размер буфера, переданного
		* пользователем меньше размера данных, доступных для чтения.
		* 2. READ_STATUS_SUCCESS - данные прочитаны успешно. Доступных данных нет
		* 3. READ_STATUS_RETRY - требуется повторный запрос на чтение.
		* 4. READ_STATUS_FAIL - при чтении произошла ошибка.
		* 
		*/
		enum share::ssl_status::read ReadData(unsigned char*, int, int&);

		BIO* input_;
		BIO* output_;
		SSL* ssl_;
	private:
		/*!
		* @brief Создает экземпляр SSL и выполняет его конфигурацию
		* @return true/false - Экземпляр создан успешно/создание(или конфигурирование) не выполнено соответственно
		*/
		virtual bool CreateSSL() = 0;

		/*!
		* @brief Создает экземпляры BIO и выполняет их конфигурирование
		* 
		* Для каждого соединения создается 2 объекта BIO (источник/приемник)
		* Конфигурирование заключается в установлении неблокирующего режима работы.
		* 
		* @return true/false - Создание и конфигурирование выполнено успешно/ безуспешно соответственно
		*/
		bool CreateBIO();

		// Удаляет память, выделенную для BIO
		void ResetBIO();
		void ResetSSL();

		bool has_data_;//!< Флаг наличия данных для отправки клиенту локальной сети
	};
}