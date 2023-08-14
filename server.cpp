#include "server.h"

bool secure_proxy::Server::Load() {
	if (!CreateBIO()) { return false; }
	if (!CreateSSL()) { ResetBIO(); return false; }

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

bool secure_proxy::Server::CreateBIO() {
	input_ = BIO_new(BIO_s_mem());
	output_ = BIO_new(BIO_s_mem());
	
	if (!input_ or !output_) { ResetBIO(); return false;}

	BIO_set_nbio_accept(input_, 1);
	BIO_set_nbio_accept(output_, 1);

	return true;
}

void secure_proxy::Server::ResetBIO() {
	if (input_) { BIO_free(input_); }
	if (output_) { BIO_free(output_); }
}

void secure_proxy::Server::ResetSSL() {
	if (ssl_) { SSL_free(ssl_); }
}

secure_proxy::Server::~Server() {
	//
	// ResetSSL использует API openssl SSL_free, 
	// который освобождает память, выделенную для SSL
	// и вызывает free для всех связанных элементов. Например, BIO.
	// Поэтому для освобождения памяти SSL и BIO достаточно выполнить
	// освобождение памяти SSL
	//	
	ResetSSL();
}