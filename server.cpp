#include "server.h"

/*!
* @details
* ��� ���������� ����� �� �������� ������������ ���������� ������������ API OpenSSL [SSL_accept](https://www.openssl.org/docs/man3.0/man3/SSL_accept.html).
*/
bool secure_proxy::Server::PerformHandshake() {
	auto handshake_code{ 0 };
	auto handshake_code_resolve{ share::ssl_status::SSL_STATUS_OK };

	handshake_code = SSL_accept(ssl_);
	handshake_code_resolve = GetSSLStatus(handshake_code);
	
	if (handshake_code_resolve == share::ssl_status::SSL_STATUS_FAIL) { return false; }

	return true;
}

/*!
* @details
* ������������ ������� �� ��������� ������ SSL � ������ ������� � ���������� SSL � BIO.
* ������������ API OpenSSL:
* * [SSL_new](https://www.openssl.org/docs/man3.0/man3/SSL_new.html) ������� SSL.
* * [SSL_set_accept_state](https://www.openssl.org/docs/man3.0/man3/SSL_set_accept_state.html) ������������� ����� ������.
* * [SSL_set_bio](https://www.openssl.org/docs/man3.0/man3/SSL_set_bio.html) ��������� ������� � �������� BIO � SSL.
*/
bool secure_proxy::Server::CreateSSL() {
	SSL_CTX* ctx = share::ServerCTXMaker::Get();

	ssl_ = SSL_new(ctx);
	if (!ssl_) { return false; }

	SSL_set_accept_state(ssl_);
	SSL_set_bio(ssl_, input_, output_);

	return true;
}