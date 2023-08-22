#include "client.h"
#include "share.h"

bool secure_proxy::Client::PerformHandshake() {
	auto handshake_code{ 0 };
	auto handshake_code_resolve{ share::ssl_status::SSL_STATUS_OK };

	handshake_code = SSL_connect(ssl_);
	handshake_code_resolve = GetSSLStatus(handshake_code);

	if (handshake_code_resolve == share::ssl_status::SSL_STATUS_FAIL) { return false; }

	return true;
}

bool secure_proxy::Client::CreateSSL() {
	SSL_CTX* ctx = share::ClientCTXMaker::Get();

	ssl_ = SSL_new(ctx);
	if (!ssl_) { return false; }

	SSL_set_connect_state(ssl_);
	SSL_set_bio(ssl_, input_, output_);

	return true;
}