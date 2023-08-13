#include "server.h"

bool secure_proxy::Server::Load() {
	if (!CreateBIO()) { return false; }
	if (!CreateSSL()) { return false; }

	return true;
}

bool secure_proxy::Server::CreateSSL() {
	SSL_CTX* ctx = share::ServerCTXMaker::Get();

	ssl_ = SSL_new(ctx);
	if (!ssl_) { return false; }

	SSL_set_accept_state(ssl_);
	SSL_set_bio(ssl_, input_, output_);

}

bool secure_proxy::Server::CreateBIO() {
	input_ = BIO_new(BIO_s_mem());
	output_ = BIO_new(BIO_s_mem());

	if (!input_ or !output_) { return false; }

	BIO_set_nbio_accept(input_, 1);
	BIO_set_nbio_accept(output_, 1);

	return true;
}