#include <iostream>
#include "config.h"
#include "share.h"

/*!
* @details
* Создание ключей выполняется с использование API OpenSSL [EVP_RSA_gen](https://www.openssl.org/docs/man3.0/man3/EVP_RSA_gen.html).
*/
share::ServerKeysMaker::ServerKeysMaker(int key_size) {
	pair_keys_ = EVP_RSA_gen(key_size);
}

/*!
* @details
*/
EVP_PKEY* share::ServerKeysMaker::Get(int key_size) {
	static ServerKeysMaker maker{key_size};
	return maker.pair_keys_;
}

/*!
* @details
* Предполагается, что сертификат и приватный ключ предварительно сгенерированы.
*/
share::RootCA::RootCA() : certificate_(nullptr), issuer_name_(nullptr), private_key_(nullptr) {
	namespace config = default_config::ca;
	
	if (certificate_ = LoadPem<X509*>(config::kPathCert, PEM_read_X509); !certificate_) { return; }

	if (private_key_ = LoadPem<EVP_PKEY*>(config::kPathPrivateKey, PEM_read_PrivateKey); !private_key_) { 
		X509_free(certificate_);
		return; 
	}

	if (issuer_name_ = X509_get_subject_name(certificate_); !issuer_name_) { 
		X509_free(certificate_);
		EVP_PKEY_free(private_key_);
		return; 
	}
}

/*!
* @details
*/
template<typename T>
T share::RootCA::LoadPem(const fs::path& pem_file_path, T(*load_function)(FILE*, T*, pem_password_cb*, void*)) {
	
	auto mode_read{ "rb" };
	
	auto pem_file_ref = tools::OpenFile(pem_file_path, mode_read);

	if (!pem_file_ref.get()) {
		return nullptr;
	}
	
	return load_function(pem_file_ref.get(), nullptr, nullptr, nullptr);

}

/*!
* @details
*/
share::RootCA* share::RootCA::Get() {
	static RootCA ca{};
	return &ca;
}

/*!
* @details
* Последовательность выполнения операции выпуска сертификата:
* * Получение CSR (ServerCSRTemplateMaker::Get).
* * Замена в CSR доменного имени.
* * Извлечение из CSR публичного ключа сервера.
* * Установка в сертификат SubjectName CSR.
* * Установка в сертификат публичного ключа.
* * Создание и установка серийного номера для сертификата.
* * Установка срока действия сертификата.
* * Установка альтернативного доменного имени в сертификат.
* * Установка в сертификат IssuerName.
* * Подписание сертификата.
* Используемый API OpenSSL:
* * [X509_REQ_get_subject_name](https://www.openssl.org/docs/man3.0/man3/X509_REQ_get_subject_name.html) возвращает SubjectName.
* * [X509_REQ_get_pubkey](https://www.openssl.org/docs/man3.0/man3/X509_REQ_get_pubkey.html) возращает публичный ключ.
* * [X509_new](https://www.openssl.org/docs/man3.0/man3/X509_new.html) создает сертификат.
* * [X509_get_serialNumber](https://www.openssl.org/docs/man3.0/man3/X509_get_serialNumber.html) возвращет серийный номер.
* * [X509_set_subject_name](https://www.openssl.org/docs/man3.0/man3/X509_set_subject_name.html) устанавливает SubjectName.
* * [X509_set_issuer_name](https://www.openssl.org/docs/man3.0/man3/X509_set_issuer_name.html) устанавливает IssuerName.
* * [X509_set_pubkey](https://www.openssl.org/docs/man3.0/man3/X509_set_pubkey.html) устанавливает публичный ключ.
* * [X509_free](https://www.openssl.org/docs/man3.0/man3/X509_free.html) очищает память, выделенную для сертификата.
*/
X509* share::RootCA::IssueCertificate(const std::string& domain) {
	X509* certificate{ nullptr };
	X509_REQ* csr{ nullptr };
	X509_NAME* subject_name{ nullptr };
	EVP_PKEY* public_key{ nullptr };
	ASN1_STRING* serial_number_property{ nullptr };
	unsigned char* serial_number{ nullptr };
	namespace config = default_config::server;

	csr = share::ServerCSRTemplateMaker::Get();

	if (!csr) { return certificate; }
	if (!ReplaceCSRDomainName(csr, domain.c_str())) { return certificate; }
	if (subject_name = X509_REQ_get_subject_name(csr); !subject_name) { return certificate; }
	if (public_key = X509_REQ_get_pubkey(csr); !public_key) { return certificate; }
	if (certificate = X509_new(); !certificate) { return certificate; }
	if (serial_number_property = X509_get_serialNumber(certificate); !serial_number_property) { X509_free(certificate); return nullptr; }
	if (serial_number = GenerateSerialNumber(); !serial_number) { X509_free(certificate); return nullptr; }
	if (!X509_set_subject_name(certificate, subject_name)) { X509_free(certificate); return nullptr; }
	if (!X509_set_issuer_name(certificate, issuer_name_)) { X509_free(certificate); return nullptr; }
	if (!X509_set_pubkey(certificate, public_key)) { X509_free(certificate); return nullptr; }
	if (!SetSerialNumber(serial_number_property, serial_number, config::kSerialNumberSize)) { X509_free(certificate); return nullptr; }
	if (!SetExpirationDate(certificate)) { X509_free(certificate); return nullptr; }
	if (!SetSubjectAltName(certificate, domain)) { X509_free(certificate); return nullptr; }
	if (!Sign(certificate)) { X509_free(certificate); return nullptr; }

	return certificate;
}

/*!
* @details
* Для создания серийного номера используется API OpenSSL [RAND_bytes](https://www.openssl.org/docs/man3.0/man3/RAND_bytes.html).
*/
unsigned char* share::RootCA::GenerateSerialNumber() {
	unsigned char* serial_number{ nullptr };
	namespace config = default_config::server;
	const auto kStatusSuccess{1};
	auto status{ 1 };

	try {
		serial_number = new unsigned char[config::kSerialNumberSize];
	}
	catch (...) {
		return nullptr;
	}

	status = RAND_bytes(serial_number, default_config::server::kSerialNumberSize);

	if (status != kStatusSuccess) { 
		delete[] serial_number;
		return nullptr; 
	}
	

	return serial_number;
}

/*!
* @details
* Используемый API OpenSSL:
* * [X509_REQ_get_subject_name](https://www.openssl.org/docs/man3.0/man3/X509_REQ_get_subject_name.html) возвращает SubjectName.
* * [X509_NAME_entry_count](https://www.openssl.org/docs/man3.0/man3/X509_NAME_entry_count.html) возвращает количество полей в SubjectName.
* * [X509_NAME_delete_entry](https://www.openssl.org/docs/man3.0/man3/X509_NAME_delete_entry.html) Удаляет запись в SubjectName по индексу.
* * [X509_NAME_add_entry_by_txt](https://www.openssl.org/docs/man3.0/man3/X509_NAME_add_entry_by_txt.html) Добавляет поле в SubjectName.
* Замена в CSR имени сервера выполняется путем удаления записи CN и добавления новой. Удаление возможно выполнить только по индексу.  
* Предполагается, что запись CN всегда имеет крайний индекс.
*/
bool share::RootCA::ReplaceCSRDomainName(X509_REQ* csr, const std::string& domain) {

	X509_NAME* subject_name{ nullptr };
	X509_NAME_ENTRY* delete_result{ nullptr };
	auto entry_count{ 0 };
	auto add_result{ 0 };
	
	subject_name = X509_REQ_get_subject_name(csr);
	entry_count = X509_NAME_entry_count(subject_name);

	if (entry_count <= 0) { return false; }
	if (delete_result = X509_NAME_delete_entry(subject_name, entry_count - 1); !delete_result) {
		return false;
	}

	add_result = X509_NAME_add_entry_by_txt(subject_name, default_config::server::kDomainLabel.c_str(), MBSTRING_ASC,
				 (const unsigned char*)domain.c_str(), -1, -1, 0);

	if (!add_result) { return false; }

	return true;
}

/*!
* @details
* Для добавления серийного номера используется API OpenSSL [ASN1_STRING_set](https://www.openssl.org/docs/man3.0/man3/ASN1_STRING_set.html).
*/
bool share::RootCA::SetSerialNumber(ASN1_STRING* property_sn, unsigned char* value, int size) {
	auto status = ASN1_STRING_set(property_sn, value, size);

	delete[] value;
	if (!status) { return false; }

	return true;
}

/*!
* @details
* Срок действия сертификата устанавливается равным 1 году.
* Используемый API OpenSSL:
* * [X509_gmtime_adj](https://www.openssl.org/docs/man3.0/man3/X509_gmtime_adj.html) устанавливате время.
*/
bool share::RootCA::SetExpirationDate(X509* certificate) {
	auto kSecsYear{ 31536000 };
	namespace config = default_config::server;

	if (!X509_gmtime_adj(X509_get_notBefore(certificate), 0)) { return false; }
	if (!X509_gmtime_adj(X509_get_notAfter(certificate), kSecsYear * config::kValidYears)) { return false; }

	return true;
}

/*!
* @details
* Необходимость установки альтернативного имени обусловлена требованием некоторых  
* клиентов к сертификатам.
*/
bool share::RootCA::SetSubjectAltName(X509* certificate, const std::string& domain) {

	GENERAL_NAMES* gens = sk_GENERAL_NAME_new_null();
	GENERAL_NAME* ext_dns = GENERAL_NAME_new();
	ASN1_IA5STRING* ia5 = ASN1_IA5STRING_new();
	ASN1_STRING_set(ia5, domain.c_str(), domain.length());
	GENERAL_NAME_set0_value(ext_dns, GEN_DNS, ia5);
	sk_GENERAL_NAME_push(gens, ext_dns);

	X509_add1_ext_i2d(certificate, NID_subject_alt_name, gens, 0, X509V3_ADD_DEFAULT);

	
	sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);

	return true;
}

/*!
* @details
* Операция выполняется с использование API OpenSSL [X509_sign](https://www.openssl.org/docs/man3.0/man3/X509_sign.html).
*/
bool share::RootCA::Sign(X509* certificate) {
	auto kSizeError{ 0 };

	if (X509_sign(certificate, private_key_, EVP_sha256()) <= kSizeError) {
		long error = ERR_get_error();
		
		if (error != 0) { return false; }
	}

	return true;
}

/*!
* @details
* Создание запроса выполняется с использованием API OpenSSL [X509_REQ_new](https://www.openssl.org/docs/man3.0/man3/X509_REQ_new.html).
* Конфигурирование запроса включает установку полей SubjectName(C, ST, L, O, CN),  
* установку версии, установку публичного ключа. Для установки версии используется  
* API OpenSSL [X509_REQ_set_version](https://www.openssl.org/docs/man3.0/man3/X509_REQ_set_version.html).
*/
share::ServerCSRTemplateMaker::ServerCSRTemplateMaker() {
	
	csr_ = X509_REQ_new();

	if (!csr_) { return; }

	if (!X509_REQ_set_version(csr_, X509_VERSION_3)) {
		X509_REQ_free(csr_);
		return;
	}

	if (!FillSubjectNameFields()) {
		X509_REQ_free(csr_);
		return;
	}

	if (!SetPublicKey()) {
		X509_REQ_free(csr_);
		return;
	}
}

/*!
* @details
* Для извлечения объекта SubjectName используется API OpenSSL [X509_REQ_get_subject_name](https://www.openssl.org/docs/man3.0/man3/X509_REQ_get_subject_name.html).
*/
bool share::ServerCSRTemplateMaker::FillSubjectNameFields() {
	
	X509_NAME* subject_name{ nullptr };

	namespace config = default_config::server;

	subject_name = X509_REQ_get_subject_name(csr_);

	if (!AddTxtEntryToSubjectName(subject_name, config::kCountryLabel, config::kCountryValue) or
		!AddTxtEntryToSubjectName(subject_name, config::kStateLabel, config::kStateValue) or
		!AddTxtEntryToSubjectName(subject_name, config::kCityLabel, config::kCityValue) or
		!AddTxtEntryToSubjectName(subject_name, config::kOrganizationLabel, config::kOrganizationValue) or
		!AddTxtEntryToSubjectName(subject_name, config::kDomainLabel, "test")
		) {
		return false;
	}

	return true;
}

/*!
* @details
* Для добавления поля используется API OpenSSL [X509_NAME_add_entry_by_txt](https://www.openssl.org/docs/man3.0/man3/X509_NAME_add_entry_by_txt.html).
*/
bool share::ServerCSRTemplateMaker::AddTxtEntryToSubjectName(X509_NAME* subject_name, const std::string& field_name, 
	const std::string& field_value) {
	return X509_NAME_add_entry_by_txt(subject_name, field_name.c_str(), MBSTRING_ASC, (const unsigned char*)field_value.c_str(), 
		-1, -1, 0);
}

/*!
* @details
* Для установки публичного ключа используется API OpenSSL [X509_REQ_set_pubkey](https://www.openssl.org/docs/man3.0/man3/X509_REQ_set_pubkey.html).
*/
bool share::ServerCSRTemplateMaker::SetPublicKey() {
	EVP_PKEY* server_keys = ServerKeysMaker::Get(default_config::server::kKeySize);

	return X509_REQ_set_pubkey(csr_, server_keys);
}

/*!
* @details
*/
X509_REQ* share::ServerCSRTemplateMaker::Get() {
	static ServerCSRTemplateMaker maker{};

	return maker.csr_;
}

/*!
* @details
* Для выполнения операций используется API OpenSSL:
* * [SSL_CTX_new](https://www.openssl.org/docs/man3.0/man3/SSL_CTX_new.html) для создания контекста.
* * [SSL_CTX_set_options](https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_options.html) для добавления параметров соединения.
* * [SSL_CTX_set_client_hello_cb](https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_client_hello_cb.html) для установки функции обработки ClientHello.
* * [SSL_CTX_set_verify](https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_verify.html) для установки флагов проверки.
*/
share::ServerCTXMaker::ServerCTXMaker(): ctx_(nullptr) {
	ctx_ = SSL_CTX_new(TLS_server_method());

	if (!ctx_) { return; }

	SSL_CTX_set_options(ctx_, SSL_OP_ALL);

	//
	SSL_CTX_set_max_proto_version(ctx_, TLS1_2_VERSION);

	SSL_CTX_set_client_hello_cb(ctx_, server_tools::ProcessClientHello, nullptr);
	SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
}

/*!
* @details
*/
SSL_CTX* share::ServerCTXMaker::Get() {
	static ServerCTXMaker maker{};
	return maker.ctx_;
}

/*!
* @details
* Для выполнения операций используется API OpenSSL:
* * [SSL_CTX_new](https://www.openssl.org/docs/man3.0/man3/SSL_CTX_new.html) для создания контекста.
* * [SSL_CTX_set_options](https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_options.html) для добавления параметров соединения.
* * [SSL_CTX_set_verify](https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_verify.html) для установки флагов проверки.
* * [SSL_CTX_load_verify_locations](https://www.openssl.org/docs/man3.0/man3/SSL_CTX_load_verify_locations.html) для загрузки доверенных сертификатов.
*/
share::ClientCTXMaker::ClientCTXMaker() {
	auto status_load_locations{ 0 };

	ctx_ = SSL_CTX_new(TLS_client_method());
	if (!ctx_) { return; }

	SSL_CTX_set_options(ctx_, SSL_OP_ALL);
	SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
	status_load_locations = SSL_CTX_load_verify_locations(ctx_, default_config::client::kCertificatesFile.c_str(), 
		                                                  default_config::client::kCertificatesStorage.c_str());
	if (!status_load_locations) {
		SSL_CTX_free(ctx_);
		ctx_ = nullptr;
	}
}

/*!
* @details
*/
SSL_CTX* share::ClientCTXMaker::Get() {
	static ClientCTXMaker maker{};
	return maker.ctx_;
}

/*!
* @details
* Функция вызывается автоматически движком OpenSSL при обнаружении сообщения ClientHello.  
* В процессе обработки, из сообщения извлекается расширение SNI. Если расширение отсутствует  
* работа функции прерывается с кодом ошибки. При получении значения SNI, выполняется запрос
* на создание сертификата. Полученный сертификат устанавливается в параметры SSL-соединения, т.е.
* полученный сертификат вернется клиенту. Если на каком-либо этапе произойдет критическая ошибка,
* работа функции прервется с кодом ошибки.
*/
int share::server_tools::ProcessClientHello(SSL* ssl, int* al, void* arg) {

	share::RootCA* ca{ nullptr };
	X509* certificate{ nullptr };
	EVP_PKEY* pair_keys{ nullptr };

	size_t extension_len{ 0 };
	const unsigned char* extension{ nullptr };
	std::string sni{};

	if (!IsExistsSNI(ssl, &extension, &extension_len)) { return SSL_CLIENT_HELLO_ERROR; }
	if (!CheckLenExtension(extension, &extension_len)) { return SSL_CLIENT_HELLO_ERROR; }
	if (!CheckTypeExtensionSNI(extension)) { return SSL_CLIENT_HELLO_ERROR; }

	if (sni = GetSNI(extension); sni.empty()) { return SSL_CLIENT_HELLO_CB; }

	ca = share::RootCA::Get();
	certificate = ca->IssueCertificate(sni);

	pair_keys = share::ServerKeysMaker::Get(default_config::server::kKeySize);

	SSL_use_certificate(ssl, certificate);
	SSL_use_PrivateKey(ssl, pair_keys);

	return SSL_CLIENT_HELLO_SUCCESS;
}

/*!
* @details
* Для выполнения операции используется API OpenSSL [SSL_client_hello_get0_ext](https://www.openssl.org/docs/man3.0/man3/SSL_client_hello_get0_ext.html).
*/
bool share::server_tools::IsExistsSNI(SSL* ssl, const unsigned char** ext, size_t* ext_len) {
	auto is_exists{ 0 };
	auto ext_len_field_size{ 2 };

	is_exists = SSL_client_hello_get0_ext(ssl, TLSEXT_NAMETYPE_host_name, ext, ext_len);

	if (!is_exists || static_cast<int>(*ext_len) <= ext_len_field_size) { return false; }

	return true;
}

/*!
* @details
* Формат расширения:  
* | len | len | type | len | len | value |
*/
bool share::server_tools::CheckLenExtension(const unsigned char*& ext, size_t* ext_len) {
	auto len{ 0 };
	size_t ext_len_field_size{ 2 };

	len = (*ext++) << 8;
	len |= *ext++;

	if (len != static_cast<decltype(len)>(*ext_len - ext_len_field_size)) {
		return false;
	}

	return true;
}

/*!
* Согласно RFC 3546, код типа расширения SNI 0 (TLSEXT_NAMETYPE_host_name)
*/
bool share::server_tools::CheckTypeExtensionSNI(const unsigned char*& extension) {
	if (*extension++ != TLSEXT_NAMETYPE_host_name) { return false; }
	return true;
}

/*!
* @details
* Размер имени сервера занимает 2 байта после типа расширения
*/
int share::server_tools::GetLenExtensionValue(const unsigned char*& extension) {
	unsigned int len{ 0 };

	len = (*extension++) << 8;
	len |= *extension++;

	return len;
}

/*!
* @details
*/
std::string share::server_tools::GetSNI(const unsigned char*& ext) {
	auto ext_len{ 0 };
	std::string sni{};
	std::unique_ptr<char[]> ext_value;

	ext_len = GetLenExtensionValue(ext);

	try {
		ext_value = std::make_unique<char[]>(ext_len + 1);
	}
	catch (...) {
		return sni;
	}

	ext_value[ext_len] = '\0';

	std::copy_n(ext, ext_len, ext_value.get());

	sni = std::string(ext_value.get());

	return sni;
}

/*!
* @details
* Создаваемые компоненты:  
* * Канал BIO (input->output)
* * Объект SSL, описывающий параметры сессии.
*/
bool share::Endpoint::Load() {
	if (!CreateBIO()) { return false; }
	if (!CreateSSL()) { ResetBIO(); return false; }

	return true;
}

/*!
* Для каждого соединения создается 2 объекта BIO (источник/приемник).  
* Конфигурирование заключается в установлении неблокирующего режима работы.  
* Создание BIO выполняется с использованием API OpenSSL:
* * [BIO_new](https://www.openssl.org/docs/man3.0/man3/BIO_new.html) для создания объекта BIO.
* * [BIO_s_mem](https://www.openssl.org/docs/man3.0/man3/BIO_s_mem.html) для использовании памяти для ввода/вывода.
*/
bool share::Endpoint::CreateBIO() {
	auto kBIOModeNonBlocking{ 1 };

	input_ = BIO_new(BIO_s_mem());
	output_ = BIO_new(BIO_s_mem());

	if (!input_ or !output_) { ResetBIO(); return false; }

	BIO_set_nbio_accept(input_, kBIOModeNonBlocking);
	BIO_set_nbio_accept(output_, kBIOModeNonBlocking);

	return true;
}

/*
* @details
* Для очистки памяти используется API OpenSSL [BIO_free](https://www.openssl.org/docs/man3.0/man3/BIO_free.html).
*/
void share::Endpoint::ResetBIO() {
	BIO_free(input_);
	BIO_free(output_);
}

/*!
* @details
* Для очистки памяти используется API OpenSSL [SSL_free](https://www.openssl.org/docs/man3.0/man3/SSL_free.html).  
* SSL_free очищает в том числе все связанные с SSL объекты.
*/
void share::Endpoint::ResetSSL() {
	if (ssl_) { SSL_free(ssl_); }
}

/*!
* @details
* Проверка выполняется с использованием API OpenSSL    
* [SSL_in_before](https://www.openssl.org/docs/man3.0/man3/SSL_in_before.html)
*/
bool share::Endpoint::IsHandshakeInit() {
	return !SSL_in_before(ssl_);
}

/*
* @details
* Если from_bio==true, будет проверен выходной BIO на наличие данных.
* Если from_bio==false, состояние будет изменено с учетом значения value.  
* Под состоянием понимается маркер has_data_. Проверка BIO выполняется с использованием  
* API OpenSSL [BIO_pending](https://www.openssl.org/docs/man3.0/man3/BIO_pending.html).
*/
void share::Endpoint::SetIsDataFlag(bool from_bio, bool value) {
	if (from_bio) {
		if (BIO_pending(output_) > 0) { has_data_ = true; }
		else { has_data_ = false; }
	}
	else {
		has_data_ = value;
	}
}

/*!
* @details
* Добавление данных в BIO выполняется с использованием API OpenSSL  
* [BIO_write](https://www.openssl.org/docs/man3.0/man3/BIO_write.html)
*/
bool share::Endpoint::SendToBIOChannel(unsigned char* data, int data_len) {
	auto bytes_writed{ 0 };

	bytes_writed = BIO_write(input_, data, data_len);
	if (bytes_writed <= 0) { return false; }

	return true;
}

/*!
* @details
* Операция выполняется с использованием API OpenSSL  
* [SSL_get_error](https://www.openssl.org/docs/man3.0/man3/SSL_get_error.html)
*/
share::ssl_status::code share::Endpoint::GetSSLStatus(int resolve_code) {
	auto error_code{ 0 };

	switch (error_code = SSL_get_error(ssl_, resolve_code); error_code) {
	case SSL_ERROR_NONE:
		return ssl_status::SSL_STATUS_OK;
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		return ssl_status::SSL_STATUS_WANT_IO;
	default:
		return ssl_status::SSL_STATUS_FAIL;
	}
}

/*!
* @details
* Читает данные из BIO в буфер, который передает пользователь. Количество прочитанных байт записывается в параметр,  
* переданный пользователем по ссылке. Ответственность за выделение и освобождение памяти для буфера возлагается на пользователя.  
* Если размер переданного буфера меньше размера данных, которые необходимо прочитать, в буфер будет записано количество байт,  
* равное его размеру и возвращен код READ_STATUS_LEFT_DATA. Для выполнения операции чтения используется API OpenSSL  
* [BIO_read](https://www.openssl.org/docs/man3.0/man3/BIO_read.html).
*/
enum share::ssl_status::read share::Endpoint::ReadData(unsigned char* buf, int buf_size, int& readed) {

	if (!buf) { return ssl_status::READ_STATUS_FAIL; }

	readed = BIO_read(output_, buf, buf_size);

	if (readed > 0) {
		if (BIO_pending(output_) > 0) { return ssl_status::READ_STATUS_LEFT_DATA; }
	}
	else {
		if (!BIO_should_retry(output_)) { return ssl_status::READ_STATUS_FAIL; }
		else { return ssl_status::READ_STATUS_RETRY; }
	}
	
	SetIsDataFlag(false, false);
	return ssl_status::READ_STATUS_SUCCESS;
}

/*!
* @details
* Операция выполняется с использованием API OpenSSL  
* [SSL_is_init_finished](https://www.openssl.org/docs/man3.0/man3/SSL_is_init_finished.html)
*/
bool share::Endpoint::IsTLSConnectionEstablished() {
	return(SSL_is_init_finished(ssl_));
}

/*!
* @details
* Маркером наличия данных является атрибут has_data_. После выполнения любой операции с данными  
* проверяется наличие результата обработки в выходном базовом потоке BIO. Если данные для чтения  
* есть, has_data_ устанавливается в true. Если данных нет, в false. При считывании данных из  
* выходного BIO, маркер has_data_ устанавливается в false.
*/
bool share::Endpoint::HasReadData() {
	return has_data_;
}

share::Endpoint::~Endpoint() {
	ResetSSL();
}
