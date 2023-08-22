#include "server.h"


bool secure_proxy::Server::PerformHandshake() {
	auto handshake_code{ 0 };
	auto handshake_code_resolve{ share::ssl_status::SSL_STATUS_OK };

	handshake_code = SSL_accept(ssl_);
	handshake_code_resolve = GetSSLStatus(handshake_code);
	
	if (handshake_code_resolve == share::ssl_status::SSL_STATUS_FAIL) { return false; }

	return true;
}

bool secure_proxy::Server::CreateSSL() {
	SSL_CTX* ctx = share::ServerCTXMaker::Get();

	ssl_ = SSL_new(ctx);
	if (!ssl_) { return false; }

	SSL_set_accept_state(ssl_);
	SSL_set_bio(ssl_, input_, output_);

	return true;
}