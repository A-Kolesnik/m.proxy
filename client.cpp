#include "client.h"
#include "share.h"

/*!
* @details
* Для выполнения одной из операций установления соединения используется API OpenSSL [SSL_connect](https://www.openssl.org/docs/man3.0/man3/SSL_connect.html).
*/
bool secure_proxy::Client::PerformHandshake() {
	auto handshake_code{ 0 };
	auto handshake_code_resolve{ share::ssl_status::SSL_STATUS_OK };

	handshake_code = SSL_connect(ssl_);
	handshake_code_resolve = GetSSLStatus(handshake_code);

	if (handshake_code_resolve == share::ssl_status::SSL_STATUS_FAIL) { return false; }

	return true;
}

/*!
* @details
* Конфигурация состоит из установки работы SSL в режиме клиента и связывание SSL с BIO.  
* Используемый API OpenSSL:
* * [SSL_new](https://www.openssl.org/docs/man3.0/man3/SSL_new.html) создает SSL.
* * [SSL_set_connect_state](https://www.openssl.org/docs/man3.0/man3/SSL_set_connect_state.html) устанавливает режим работы.
* * [SSL_set_bio](https://www.openssl.org/docs/man3.0/man3/SSL_set_bio.html) связывает входной и выходной BIO с SSL.
*/
bool secure_proxy::Client::CreateSSL() {
	SSL_CTX* ctx = share::ClientCTXMaker::Get();

	ssl_ = SSL_new(ctx);
	if (!ssl_) { return false; }

	SSL_set_connect_state(ssl_);
	SSL_set_bio(ssl_, input_, output_);

	return true;
}