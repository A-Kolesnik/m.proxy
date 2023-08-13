#include "proxy.h"
#include "share.h"

bool secure_proxy::Init() {

	if (!init_tools::GenerateServerKeys()) { return false; }
	if (!init_tools::GenerateCSRTemplate()) { 
		reset_tools::ResetServerKeys(); 
		return false; 
	}
	if (!init_tools::LoadCAKeyData()) { 
		reset_tools::ResetServerKeys();
		reset_tools::ResetCSR();
		return false; 
	}
	if (!init_tools::LoadCtx()) {
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

bool secure_proxy::init_tools::GenerateServerKeys() {

	namespace config = default_config::server;

	if (!share::ServerKeysMaker::Get(config::kKeySize)) { return false; }
	return true;
}

bool secure_proxy::init_tools::GenerateCSRTemplate() {
	if (!share::ServerCSRTemplateMaker::Get()) { return false; }

	return true;
}

bool secure_proxy::init_tools::LoadCAKeyData() {

	share::RootCA* ca = share::RootCA::Get();

	if (!ca->GetCertificate() or !ca->GetPrivateKey() or !ca->GetIssuerName()) {
		return false;
	}

	return true;
}

bool secure_proxy::init_tools::LoadCtx() {

	if (!share::ServerCTXMaker::Get()) { return false; }

	return true;
}

void secure_proxy::reset_tools::ResetServerKeys() {
	EVP_PKEY* keys = share::ServerKeysMaker::Get(default_config::server::kKeySize);
	EVP_PKEY_free(keys);
}

void secure_proxy::reset_tools::ResetCA() {
	share::RootCA* ca = share::RootCA::Get();

	X509_free(ca->GetCertificate());
	EVP_PKEY_free(ca->GetPrivateKey());
}

void secure_proxy::reset_tools::ResetCSR() {
	X509_REQ* csr = share::ServerCSRTemplateMaker::Get();
	X509_REQ_free(csr);
}

void secure_proxy::reset_tools::ResetCTX() {
	SSL_CTX* ctx = share::ServerCTXMaker::Get();
	SSL_CTX_free(ctx);
}

bool secure_proxy::Proxy::Load() {
	if (!server_.Load()) { return false; }
}