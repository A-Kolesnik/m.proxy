#include "proxy.h"
#include "share.h"

bool secure_proxy::Init() {
	
	if (!init_tools::GenerateServerKeys() or
		!init_tools::GenerateCSRTemplate() or
		!init_tools::LoadCAKeyData() or
		!init_tools::LoadCtx()
		) {
		Reset();
		return false;
	}
	
	return true;
}

void secure_proxy::Reset() {

	reset_tools::ResetServerKeys();
	reset_tools::ResetCA();
	reset_tools::ResetCSR();
	reset_tools::ResetCTX();
}

/*
* @details
* Создание ключей выполняется с использованием статического метода класса  
* ServerKeysMaker Get().
*/
bool secure_proxy::init_tools::GenerateServerKeys() {

	namespace config = default_config::server;

	if (!share::ServerKeysMaker::Get(config::kKeySize)) { return false; }
	return true;
}

/*!
* @details
* Создание шаблона запроса выполняется с использованием статического метода  
* класса ServerCSRTemplateMaker Get().
*/
bool secure_proxy::init_tools::GenerateCSRTemplate() {
	if (!share::ServerCSRTemplateMaker::Get()) { return false; }

	return true;
}

/*!
* @details
* * Загружает самоподписанный сертификат
* * Загружает приватный ключ
* * Извлекает из сертификата IssuerName
* Сертификат и приватный ключ должны быть сгенерированы заранее и  
* предоставлены в виде файлов в PEM-формате. Пути к файлам указываются  
* в config.h.
*/
bool secure_proxy::init_tools::LoadCAKeyData() {

	share::RootCA* ca = share::RootCA::Get();

	if (!ca->GetCertificate() or !ca->GetPrivateKey() or !ca->GetIssuerName()) {
		return false;
	}

	return true;
}

/*!
* @details
* Создание контекстов выполняется с использованием статисеского метода Get():  
* * класса ServerCTXMaker для сервера
* * класса ClientCTXMaker для клиента
*/
bool secure_proxy::init_tools::LoadCtx() {
	if (!share::ServerCTXMaker::Get()) { return false; }
	if (!share::ClientCTXMaker::Get()) { return false; }

	return true;
}

/*!
* @details
* Освобождение памяти выполняется с использованием API OpenSSL  
* [EVP_PKEY_free](https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_free.html)
*/
void secure_proxy::reset_tools::ResetServerKeys() {
	EVP_PKEY* keys = share::ServerKeysMaker::Get(default_config::server::kKeySize);
	EVP_PKEY_free(keys);
}

/*
* @details
* Освобождение памяти выполняется с использованием API OpenSSL:  
* * [X509_free](https://www.openssl.org/docs/man3.0/man3/X509_free.html) для сертификата.
* * [EVP_PKEY_free](https://www.openssl.org/docs/man3.0/man3/EVP_PKEY_free.html) для ключа.
*/
void secure_proxy::reset_tools::ResetCA() {
	share::RootCA* ca = share::RootCA::Get();

	X509_free(ca->GetCertificate());
	EVP_PKEY_free(ca->GetPrivateKey());
}

/*
* @details
* Освобождение памяти выполняется с использованием API OpenSSL  
* [X509_REQ_free](https://www.openssl.org/docs/man3.0/man3/X509_REQ_free.html)
*/
void secure_proxy::reset_tools::ResetCSR() {
	X509_REQ* csr = share::ServerCSRTemplateMaker::Get();
	X509_REQ_free(csr);
}

/*
* @details
* Освобождение памяти выполняется с использованием API OpenSSL
* [SSL_CTX_free](https://www.openssl.org/docs/man3.0/man3/SSL_CTX_free.html)
*/
void secure_proxy::reset_tools::ResetCTX() {
	SSL_CTX* ctx_server = share::ServerCTXMaker::Get();
	SSL_CTX* ctx_client = share::ClientCTXMaker::Get();

	SSL_CTX_free(ctx_client);
	SSL_CTX_free(ctx_server);
}

/*!
* @details
* Под сервером и клиентом понимаются части данного класса:  
* серверная в локальной сети и клиентская во внешней сети.
*/
bool secure_proxy::Proxy::Load() {
	if (!server_.Load()) { return false; }
	if (!client_.Load()) { return false; }

	return true;
}

/*!
* Обработка включает следующие операции:
*  * Добавление сообщения во входной BIO.
*  * Выполнение операции установления соединения с Proxy сервером(
*    если не установлено).
*  * Расшифровка сообщения и трансляция его на PIN.
*  * Шифрование сообщение Proxy клиентом.
* Если один из шагов завершится с критической ошибкой, метод вернет false, что
* должно привести к разрыву соединения.
*/
bool secure_proxy::Proxy::ProcessLANClientMessage(unsigned char* message, int message_len) {

	if (!server_.SendToBIOChannel(message, message_len)) { return false; }

	if (!server_.IsTLSConnectionEstablished()) {
		if (!EstablishLANConnection()) { return false; }
	}
	else {
		if (!ProcessApplicationData(true)) { return false; }
	}

	return true;
}

/*!
* @details
* Обработка включает следующие операции:
*  * Добавление сообщения во входной BIO.
*  * Выполнение операции установления соединения с Proxy клиентом(
*    если не установлено).
*  * Расшифровка сообщения и трансляция его на PIN.
*  * Шифрование сообщение Proxy сервером.
* Если один из шагов завершится с критической ошибкой, метод вернет false, что
* должно привести к разрыву соединения.
*/
bool secure_proxy::Proxy::ProcessWANServerMessage(unsigned char* message, int message_len) {
	
	if (!client_.SendToBIOChannel(message, message_len)) { return false; }
	
	if (!client_.IsTLSConnectionEstablished()) {
		if (!EstablishWANConnection()) { return false; }
	}
	else {
		if (!ProcessApplicationData(false)) { return false; }
	}

	return true;
}

/*!
* @details
* т.к. объекты BIO, связанные с SSL, работают в неблокирующем режиме,
* установление соединения происходит не сразу. После каждого успешного
* шага соединения, результат помещается в выходной BIO. Для передачи данных
* между клиентом локальной сети и сервером во внешней сети, необходимо
* установить соединения клиента LAN с сервером Proxy и клиента Proxy
* с сервером WAN. В данной реализации, установление соединения клиента Proxy 
* с внешним сервером будет инициировано после обработки клиентом LAN ответа от
* Proxy сервера на сообщение ClientHello. После установления соединения Proxy клиента с 
* WAN сервером, будет продолжено установление соединения Proxy сервера с LAN клиентом.
* Причем, установление соединения для различных версий протокола будет отличаться. В частности,
* изменения в установлении соединения были внесены в версию протокола 1.3. Одно из изменений, которое
* можно заметить в реализации - это передача сообщения Finished. В версии TLS 1.3 данное сообщение
* передается с первым зашифрованным сообщением. В предыдущих версиях протокола, соединение считалось
* неустановленным, пока узлы не обменялись сообщением Finished. Т.е. данные и Finished передавались 
* отдельно друг от друга. 
*/
bool secure_proxy::Proxy::EstablishLANConnection() {
	
	if (!server_.IsHandshakeInit()) {
		if (!PerformLANHandshake()) { return false; }
		if (!ConfigureClientProxyGivenSNI()) { return false; }
	}
	else {
		if (!client_.IsTLSConnectionEstablished()) {
			if (!PerformWANHandshake()) { return false; }
		}
		else {
			if (!PerformLANHandshake()) { return false; }
		}
	}

	return true;
}

/*!
* @details
*/
bool secure_proxy::Proxy::EstablishWANConnection() {
	
	if (!PerformWANHandshake()) { return false; }

	if (client_.IsTLSConnectionEstablished() ) {

		client_.SetIsDataFlag(false, false);
		if (!PerformLANHandshake()) { return false; }
	}

	return true;
}

/*!
* @details
* Если операция Handshake выполнена успешно, выполняется проверка
* наличия данных для чтения в выходном BIO.
*/
bool secure_proxy::Proxy::PerformLANHandshake() {
	if (!server_.PerformHandshake()) { return false; }
	server_.SetIsDataFlag();
	
	return true;
}

/*!
* @details
* Если операция Handshake выполнена успешно, выполняется проверка
* наличия данных для чтения в выходном BIO.
*/
bool secure_proxy::Proxy::PerformWANHandshake() {
	if (!client_.PerformHandshake()) { return false; }
	client_.SetIsDataFlag();

	return true;
}

/*!
* @details
* Выполняет шифрование/расшифрование данных, обмен полученными данными
* между клиентской и серверной частью Proxy. Последовательность операций:
*  * Полученные данные расшировываются.
*  * Открытые данные транслируются на PIN.
*  * Выполняется шифрование на противоположной стороне Proxy. Результат шифрования будет расположен в выходном BIO.
*  Перед вызовом метода, сообщение помещается во входной BIO, который является  источником данных для расшифровывания.
*  Особенностью работы является возможность отправки одной из сторон после установления соединения системных сообщений. 
*  Подобное событие будет обработано корректно, а именно системное сообщение будет обработано соответствующей стороной, и 
*  результат будет записан в выходной BIO. Если отправленное сообщение будет означать разрыв соединения или одна из сторон 
*  не сможет корректно его обработать, метод вернет false, что будет означать разрыв соединения.
*/
bool secure_proxy::Proxy::ProcessApplicationData(bool is_server) {
	share:: Endpoint* role{ nullptr };
	unsigned char* decrypted_data{nullptr};
	int decrypted_data_size{ 0 };

	if (is_server) { role = &server_; }
	else { role = &client_; }

	if (!DecryptData(role, decrypted_data, decrypted_data_size)) { return false; }

	if (decrypted_data_size == 0) {
		if (decrypted_data) { tools::ClearMemory(decrypted_data, true); }
		role->SetIsDataFlag();
		return true; 
	}

	/*
	* Отправить на PIN
	*/

	if (is_server) {
		if (!EncryptData(&client_, decrypted_data, decrypted_data_size)) { return false; }
	}
	else {
		if (!EncryptData(&server_, decrypted_data, decrypted_data_size)) { return false; }
	}

	if (decrypted_data) { tools::ClearMemory(decrypted_data, true); }

	return true;
}

/*!
* @details
* Расшифрование происходит с использование API OpenSSL [SSL_read](https://www.openssl.org/docs/man3.0/man3/SSL_read.html).
* Шифрованные данные извлекаются из входного BIO. Если для расшифрования недостаточно данных,
* ядро OpenSSL считает данные из BIO, закэширует их и будет ждать следующую порцию данных.
* В этом случае, метод вернет true, но данных для чтения в BIO не будет. Когда данных будет достаточно,
* они будут расшифрованы
*/
bool secure_proxy::Proxy::DecryptData(share::Endpoint* role, unsigned char*& buf, int& decrypted) {
	auto bytes_left_to_read{ 0 };
	auto default_size{ 65536 };
	auto read_status_code_resolve{ share::ssl_status::SSL_STATUS_OK };
	auto read_chunk_size{ default_size };
	auto return_code{ true };
	auto readed{ 0 };
	auto ssl_pending{ 0 };
	
	if (!tools::AllocateMemory(buf, default_size)) { return false; }

	while (true) {
		readed = SSL_read(role->ssl_, buf + decrypted, read_chunk_size);
		if (readed <= 0) { break; }

		decrypted += readed;
		bytes_left_to_read = SSL_pending(role->ssl_);

		if ( bytes_left_to_read > 0) {
			if (!tools::ExpandBuffer(buf, default_size + bytes_left_to_read)) { return_code = false; break; }
			read_chunk_size = bytes_left_to_read;
		}
	}

	if (!return_code) {
		if (buf) { tools::AllocateMemory(buf, true); }
	}
	else {
		read_status_code_resolve = role->GetSSLStatus(readed);
		if (read_status_code_resolve == share::ssl_status::SSL_STATUS_FAIL) { return_code = false; }
	}

	return return_code;
}

/*!
* @details
* Шифрование выполняется с использование API OpenSSL [SSL_write](https://www.openssl.org/docs/man3.0/man3/SSL_write.html),
* после чего данные записываются в выходной BIO.
*/
bool secure_proxy::Proxy::EncryptData(share::Endpoint* role, unsigned char* data, int data_len) {
	int write_status{ 0 };
	int write_status_resolve{ 0 };
	
	write_status = SSL_write(role->ssl_, data, data_len);
	write_status_resolve = role->GetSSLStatus(write_status);
	
	role->SetIsDataFlag();

	if (write_status_resolve == share::ssl_status::SSL_STATUS_FAIL) { return false; }

	return true;
}

/*!
* @details
* Сброс состояния BIO. Выполняется с использованием API OpenSSL 
* [BIO_reset](https://www.openssl.org/docs/man3.0/man3/BIO_reset.html).
*/
void secure_proxy::Proxy::ResetBIOBuffer(BIO* bio) {
	BIO_reset(bio);
}

/*!
* @details
* Конфигурирование включает установку расширения SNI и ожидаемого имени сервера.
* Имя сервера извлекается из серверной части Proxy с использованием API OpenSSL
* [SSL_get_servername](https://www.openssl.org/docs/man3.0/man3/SSL_get_servername.html).
*/
bool secure_proxy::Proxy::ConfigureClientProxyGivenSNI() {
	std::string host_name{};

	host_name = SSL_get_servername(server_.ssl_, TLSEXT_NAMETYPE_host_name);

	if (!SetSNI(host_name)) { return false; }
	if (!SetExpectedHostName(host_name)) { return false; }

	return true;
}

/*!
* @details
* Расширение SNI необходимо при формировании клиентом сообщения ClientHello.
* Используя данное расширение, сервер определяет какой сертификат использовать
* для ответа клиенту. Добавление SNI выполняется с использованием API OpenSSL
* [SSL_set_tlsext_host_name](https://www.openssl.org/docs/man3.0/man3/SSL_set_tlsext_host_name.html).
*/
bool secure_proxy::Proxy::SetSNI(std::string sni) {
	return SSL_set_tlsext_host_name(client_.ssl_, sni.c_str());
}

/*!
* @details
* В процесс валидации сертификата возможно включить дополнительну операцию - 
* проверку имени сервера. В этом случае, имя сервера извлекается из сертификата
* и соотносится с ожидаемым именем сервера, установленном на клиенте. Установка
* ожидаемого имени сервера и конфигурация процесса валидации выполняется с использованием
* API OpenSSL:
*   * [SSL_set_hostflags](https://www.openssl.org/docs/man3.0/man3/SSL_set1_host.html): 
*     устанавливает флаги проверки. В текущей реализации установлен флаг
*     [X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS](https://www.openssl.org/docs/man3.0/man3/X509_check_host.html).
*   * [SSL_set1_host](https://www.openssl.org/docs/man3.0/man3/SSL_set1_host.html):
*     устанавливает ожидаемое имя сервера.
*/
bool secure_proxy::Proxy::SetExpectedHostName(std::string host_name) {
	SSL_set_hostflags(client_.ssl_, X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS);

	return SSL_set1_host(client_.ssl_, host_name.c_str());
}