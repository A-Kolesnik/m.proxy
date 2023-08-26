/*!
* @file
* @brief Описывает разделяемые компоненты TLS-части программного модуля.
*/
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
		/// Набор возможных статусов выполнения операций в рамках соединения
		enum code {
			SSL_STATUS_WANT_IO, //!< Клиент/сервер ожидает данных для записи или чтения
			SSL_STATUS_FAIL,    //!< Критическая ошибка
			SSL_STATUS_OK       //!< Операция выполнена успешно
		};

		/// Набор возможных статусов при чтении данных из BIO
		enum read {
			READ_STATUS_LEFT_DATA, //!< Прочитаны не все данные
			READ_STATUS_SUCCESS,   //!< Все данные прочитаны успешно
			READ_STATUS_RETRY,     //!< Необходимо обратиться к BIO позже
			READ_STATUS_FAIL       //!< Критическая ошибка
		};
	}

	namespace server_tools {
		/*!
		* @brief Обрабатывает сообщение ClientHello.
		* @retval 1 Обработка выполнена успешно.
		* @retval 0 В процессе обработки возникла критическая ошибка.
		*/
		int ProcessClientHello(SSL*, int*, void*);

		/*!
		* @brief Проверяет наличие расширения SNI
		* @retval true  Расширение есть
		* @retval false Расширения нет
		*/
		bool IsExistsSNI(SSL*, const unsigned char**, size_t*);
		
		/*!
		* @brief Вычисляет размер значения имени сервера.
		* 
		* @retval[in] Расширение.
		* 
		* @return Размер имени сервера.
		*/
		int GetLenExtensionValue(const unsigned char*&);
		
		/*!
		* @brief Вычисляет размер расширения и выполняет проверку его валидности.
		* 
		* @param[in] ext	 Расширение RFC 3546 / 6066.
		* @param[in] ext_len Размер расширения.
		* 
		* @retval true  Размер расширения валиден.
		* @retval false Размер расширения не валиден.
		*/
		bool CheckLenExtension(const unsigned char*&, size_t*);

		/*!
		* @brief Выполняет соответствие типа расширения расширению SNI.
		* 
		* @param[in] extension Расширение.
		* 
		* @retval true  Тип расширения - расширение SNI.
		* @retval false Расширение не является SNI.
		*/
		bool CheckTypeExtensionSNI(const unsigned char*&);

		/*!
		* @brief Извлекает значение имени сервера из расширения.
		* 
		* @param[in] ext Расширение.
		*
		* @return Имя сервера.
		*/
		std::string GetSNI(const unsigned char*&);
	}

	/*!
	* @brief Описывает интерфейс создания ключей сервера.
	* @details
	* Реализация основана на использовании паттерна Singleton. Это обосновано  
	* тем, что для каждого соединения необходимо выполнять создание сертификата, что  
	* требует наличие запроса CSR. Для создания CSR требуются ключи сервера. Генерация  
	* ключей является временнозатратной операцией. Поэтому ключи будут созданы при  
	* инициализации модуля и использованы для всех соединений.
	*/
	class ServerKeysMaker {

	public:
		ServerKeysMaker(const ServerKeysMaker&) = delete;
		ServerKeysMaker& operator=(const ServerKeysMaker&) = delete;

		/*!
		* @brief Выполняет запрос на создание(если не созданы) ключей сервера.
		* 
		* @param[in] key_size Размер ключа.
		* 
		* @return Пара ключей сервера.
		*/
		static EVP_PKEY* Get(int);
	protected:
		/*!
		* @brief Создает ключи сервера.
		* 
		* @param[in] key_size Размер ключа.
		*	Nothing.
		*/
		explicit ServerKeysMaker(int);

	private:
		EVP_PKEY* pair_keys_; //!< Пара RSA ключей сервера.
	};

	/*!
	* @brief Описывает интерфейс создания шаблона запроса к CA на выдачу сертификата.
	* @details
	* Реализация основана на использовании паттерна Singleton. Т.к. модуль работает в однопоточном режиме,  
	* для каждого нового соединения можно использовать один объект CSR, изменяя только поле CN (domain name).  
	* Остальные поля остаются неизменными. При отправке запроса к стороннему CA, CSR подписывается приватным  
	* ключом сервера, для проверки на подлинность. Поскольку CA реализован в модуле, данная проверка выполнять не будет.  
	* Операция подписи также будет отсутствовать.
	*/
	class ServerCSRTemplateMaker {
	public:
		ServerCSRTemplateMaker(const ServerCSRTemplateMaker&) = delete;
		ServerCSRTemplateMaker& operator=(const ServerCSRTemplateMaker&) = delete;

		/*!
		* @brief Выполняет запрос на создание(если не создан) шаблона запроса CSR.
		* @return Шаблон запроса CSR.
		*/
		static X509_REQ* Get();
	protected:
		/*!
		* @brief Создает и конфигурирует CSR.
		*	Nothing.
		*/
		ServerCSRTemplateMaker();
	private:
		/*!
		* @brief Заполняет поля в SubjectName CSR.
		* 
		* @retval true  Операция выполнена успешно.
		* @retval false Произошла критическая ошибка.
		*/
		bool FillSubjectNameFields();

		/*!
		* @brief Добавляет поле в SubjectName CSR.
		* 
		* @param[in, out] subject_name Объект SubjectName из CSR.
		* @param[in]      field_name   Нименование поля.
		* @param[in]      field_value  Значение поля.
		* 
		* @retval true  Поле успешно добавлено.
		* @retval false Произошла критическая ошибка.
		*/
		bool AddTxtEntryToSubjectName(X509_NAME*,const std::string&, const std::string&);
		
		/*!
		* @brief Устанавливает публичный ключ сервера в CSR.
		* 
		* @retval true  Операция выполнена успешно
		* @retval false Произошла критическая ошибка
		*/
		bool SetPublicKey();

		X509_REQ* csr_; //!< Шаблон запроса на выдачу сертификата CSR.
	};

	/*!
	* @brief Описывает интерфейс создания контекста сервера.  
	* @details
	* Реализация основана на использовании паттерна Singleton. Используя контекст, будут соданы экземпляры SSL.  
	* Для всех соединений параметры сервера Proxy будут неизменны за исключением сертификата. API OpenSSL позволяет  
	* указывать сертификат, используемый сервером двумя способами:
	* * В контексте перед созданием экземпляра сессии SSL.
	* * Непосредственно в экземпляре SSL.
	* Реализация данного модуля предполагает использование способа 2. Это обусловлено тем, что установка используемого  
	* сертификата выполняется после его генерации. Для генерации необходимо расширение SNI, содержащееся в сообщении ClientHello.  
	* Обработка ClientHello выполняется в функции обратного вызова, которая вызывается SSL_accept. Перед вызовом SSL_accrpt объект SSL
	* должен быть создан. Т.к. объект SSL создается на базе контекста, то изменение параметров сессии, в частности, установка используемого  
	* сертификата, выполняется непосредственно, в экземпляре сессии. Поэтому для всех соединений возможно использование одного контекста для сервера.
	*/

	class ServerCTXMaker {
	public:
		ServerCTXMaker(const ServerCTXMaker&) = delete;
		ServerCTXMaker& operator=(const ServerCTXMaker&) = delete;

		/*!
		* @brief Выполняет запрос на создание (если не создан) контекста для сервера.
		* 
		* @return Контекст сервера.
		*/
		static SSL_CTX* Get();
	protected:
		/*!
		* @brief Создает и конфигурирует контекст сервера.
		*	Nothing.
		*/
		ServerCTXMaker();
	private:
		SSL_CTX* ctx_; //!< Контекст сервера.
	};

	/*!
	* @brief Описывает интерфейс создания контекста клиента.
	* @details
	* Реализация основана на использовании паттерна Singleton. В WAN Proxy выступает клиентом. Для всех соединени  
	* параметры будут неизменяемые. Исключением является расширение SNI сообщения ClientHello. Поэтому для создания  
	* экземпляра класса SSL для всех соединений будет использован один экземпляр контекста с предустановленными
	* параметрами. Расширение SNI будет добавлено в каждый отдельный экземпляр SSL.
	*/
	class ClientCTXMaker {
	public:
		ClientCTXMaker(const ClientCTXMaker&) = delete;
		ClientCTXMaker& operator=(const ClientCTXMaker&) = delete;

		/*!
		* @brief Выполняет запрос на создание (если не создан) контекста для клиента.
		*
		* @return Контекст клиента.
		*/
		static SSL_CTX* Get();
	protected:

		/*!
		* @brief Создает и конфигурирует контекст клиента.
		*	Nothing.
		*/
		ClientCTXMaker();
	private:
		SSL_CTX* ctx_; //!< Контекст клиента.
	};
	
	/*!
	* @brief Описывает интерфейс создания центра сертификации.
	* @details
	* Реализация основана на использовании паттерна Singleton. Для всех соединений будет использован  
	* один центр сертификации.
	*/
	class RootCA {
	public:
		RootCA(const RootCA&) = delete;
		RootCA& operator=(const RootCA&) = delete;

		/*!
		* @brief Выополняет запрос на создание (если не создан) центра сертификации.
		* 
		* @return Указатель на экземпляр центра сертификации.
		*/
		static RootCA* Get();

		/*!
		* @brief Выпускает сертификат.
		* 
		* @param[in] domain Доменной имя
		* 
		* @return Указатель на выпущенный сертификат.
		*/
		X509* IssueCertificate(const std::string&);

		/*!
		* @brief Возвращает сертификат.
		* 
		* @return Сертификат.
		*/
		X509* GetCertificate() { return certificate_; }

		/*!
		* @brief Возвращает IssuerName.
		*
		* @return IssuerName.
		*/
		X509_NAME* GetIssuerName() { return issuer_name_; }

		/*!
		* @brief Возвращает приватный ключ.
		*
		* @return Приватный ключ.
		*/
		EVP_PKEY* GetPrivateKey() { return private_key_; }

	protected:
		/*!
		* @brief Загружает сертификат и приватный ключ CA.
		*	Nothing.
		*/
		RootCA();
	private:
		// Выполняет загрузку файла в PEM формате
		/*
		* @brief Загружает файл в PEM-формате.
		* 
		* @tparam Возвращаемое значение функции загрузки компонента в PEM-формате.
		* @param[in] pem_file_path Путь к файлу.
		* @param[in] load_function Вызываемая функция.
		* 
		* @return Загруженный компонент.
		*/
		template<typename T>
		T LoadPem(const fs::path&, T(*load_function)(FILE*, T*, pem_password_cb*, void*));

		/*!
		* @brief Генерирует серийный номер сертификата
		* 
		* @return Указатель на серийный номер сертификата.
		*/
		unsigned char* GenerateSerialNumber();

		/*!
		* @brief Заменяет имя сервера в CSR
		* 
		* @param[in,out] csr    Запрос на выпуск сертификата.
		* @param[in]     domain Доменное имя, для которого необходимо выпустить сертификат.
		* 
		* @retval true  Замена выполнена успешно
		* @retval false Произошла критическая ошибка
		*/
		bool ReplaceCSRDomainName(X509_REQ*, const std::string&);

		/*!
		* @brief Устанавливает серийный номер.
		* 
		* @param[in, out] property_sn Серийный номер сертификата.
		* @param[in]      value Значение серийного номера.
		* @param[in]      size Размер серийного номера.
		* 
		* @retval true  Серийный номер добавлен успешно.
		* @retval false Произошла критическая ошибка.
		*/
		bool SetSerialNumber(ASN1_STRING*, unsigned char*, int);
		
		/*!
		* @brief Устанавливает срок действия сертификата.
		* 
		* @param[in, out] certificate Сертификат.
		* 
		* @retval true  Срок действия установлен успешно.
		* @retval fasle Произошла критическая ошибка.
		*/
		bool SetExpirationDate(X509*);

		/*!
		* @brief Устанавливает альтернативное имя сервера.
		* 
		* @param[in, out] certificate Сертификат.
		* @param[in]      domain Альтернативное имя сервреа.
		* 
		* @retval true  Альтернативное имя установлено успешно.
		* @retval false Произошла критическая ошибка.
		*/
		bool SetSubjectAltName(X509*, const std::string&);

		/*!
		* @brief Подписывает сертификат.
		* 
		* @param[in, out] certificate Сертификат.
		* 
		* @retval true  Сертификат подписан успешно.
		* @retval false Произошла критическая ошибка.
		*/
		bool Sign(X509*);

		X509* certificate_;     //!< Сертификат CA. 
		X509_NAME* issuer_name_;//!< Данные о издателе сертификата.
		EVP_PKEY* private_key_; //!< Приватный ключ CA.
	};

	/*!
	* @brief Абстрактный класс описывает общий интерфейс для клинета и сервера.
	*/
	class Endpoint {
	public:
		Endpoint() : input_(nullptr), output_(nullptr), ssl_(nullptr), has_data_(false) {};
		~Endpoint();

		/*!
		* @brief Создает компоненты для организации и поддержания соединения узлом (клиент/сервер).
		* @retval true  Создание выполнено успешно
		* @retval false При создании произошла критическая ошибка
		*/
		bool Load();

		/*!
		* @brief Выполняет очередной шаг процедуры установления соединения.
		* @retval true  Шаг выполнен успешно
		* @retval false При выполнении шага произошла критическая ошибка или обрабатываемое сообщение  
		* требует разрыва соединения.
		*/
		virtual bool PerformHandshake() = 0;

		/*!
		* @brief Определяет, был ли инициирован Handshake
		* @retval true  Handshake был инициирован
		* @retval false Handshake не был инициирован
		*/
		bool IsHandshakeInit();

		/*!
		* @brief Определяет наличие ошибок при выполнении операций с экземпляром SSL.
		* @retval ssl_status::SSL_STATUS_OK      Ошибок в очереди нет.
		* @retval ssl_status::SSL_STATUS_WANT_IO Состояние ожидания операции чтения/записи (не ошибка)
		* @retval ssl_status::SSL_STATUS_FAIL    Ошибка
		*/
		enum ssl_status::code GetSSLStatus(int);

		/*!
		* @brief Изменяет состояния экземпляра в отношении данных для чтения.
		* @param[in] from_bio Состояние определяется наличием данных в выходном BIO
		* @param[in] value    Значение для установки, если from_bio == false
		*	Nothing.
		*/
		void SetIsDataFlag(bool from_bio=true, bool value=true);

		/*!
		* @brief Добавляет данные во входной BIO.
		* 
		* @param[in] data     Данные для добавления
		* @param[in] data_len Размер данных
		* 
		* @retval true  Данные добавлены успешно.
		* @retval false При добавлении данных произошла критическая ошибка.
		*/
		bool SendToBIOChannel(unsigned char*, int);

		/*!
		* @brief Определяет состояние TLS-соединени
		* @retval true  Соединение установлено для безопасной передачи данных.
		* @retval false Соединение не готово для безопасной передачи данных.
		*/
		bool IsTLSConnectionEstablished();

		/*!
		* @brief Определяет наличие данных для чтения и отправки клиенту/серверу
		* @retval true  Есть данные для чтения
		* @retval false Нет данных для чтения
		*/
		bool HasReadData();
		

		/*!
		* @brief Чтение данных для отправки клиенту/серверу
		*
		* @param[out] buf      Область памяти, куда будут записаны прочитанные данные
		* @param[in]  buf_size Размер области памяти
		* @param[out] readed   Количество записанных байт
		* 
		* @retval READ_STATUS_LEFT_DATA - прочитаны не все данные. Переход в это состояние возможен  
		* в случае, если размер буфера, переданного пользователем меньше размера данных, доступных для чтения.
		* @retval READ_STATUS_SUCCESS   - данные прочитаны успешно. Доступных данных нет.
		* @retval READ_STATUS_RETRY     - требуется повторный запрос на чтение.
		* @retval READ_STATUS_FAIL      - при чтении произошла ошибка.
		*/
		enum share::ssl_status::read ReadData(unsigned char*, int, int&);

		BIO* input_; //!< Входной поток BIO
		BIO* output_;//!< Выходной поток BIO
		SSL* ssl_;   //!< Описыает парметры и состояние соединения
	private:
		/*!
		* @brief Создает экземпляр SSL и выполняет его конфигурацию
		* 
		* @retval true  Экземпляр создан и сконфигурирован успешно.
		* @retval false Произошла критическая ошибка при создании или конфигурации экземпляра SSL.
		*/
		virtual bool CreateSSL() = 0;

		/*!
		* @brief Создает экземпляры BIO и выполняет их конфигурирование
		* 
		* @retval true  Создание и конфигурирование выполнено успешно.
		* @retval false При создании произошла критическая ошибка.
		*/
		bool CreateBIO();

		/*!
		* @brief Очищает память, выделенную для BIO.
		*	Nothing.
		*/
		void ResetBIO();

		/*!
		* @Очищает память, выделенную для SSL.
		*	Nothing.
		*/
		void ResetSSL();

		bool has_data_;//!< Флаг наличия данных для отправки клиенту/серверу
	};
}