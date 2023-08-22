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
	if (!share::ClientCTXMaker::Get()) { return false; }

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
	if (!client_.Load()) { return false; }

	return true;
}

bool secure_proxy::Proxy::ProcessLANClientMessage(unsigned char* message, int message_len) {

	if (!server_.SendToBIOChannel(message, message_len)) { return false; }

	if (!server_.IsTLSConnectionEstablished()) {
		if (!EstablishLANConnection()) { return false; }
	}
	else {
		if (!ProcessApplicationData(message, message_len, true)) { return false; };
	}

	return true;
}

bool secure_proxy::Proxy::ProcessWANServerMessage(unsigned char* message, int message_len) {
	
	if (!client_.SendToBIOChannel(message, message_len)) { return false; }
	
	if (!client_.IsTLSConnectionEstablished()) {
		if (!EstablishWANConnection()) { return false; }
	}
	else {
		if (!ProcessApplicationData(message, message_len, false)) { return false; }
	}
	

	return true;
}

bool secure_proxy::Proxy::EstablishLANConnection() {
	
	if (!server_.IsHandshakeInit()) {
		if (!PerformLANHandshake()) { return false; }

		/*
		* Если не будет SNI, шаг рукопожатия не будет выполнен
		*/
		if (!SetServerName()) { return false; }
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

bool secure_proxy::Proxy::EstablishWANConnection() {
	
	if (!PerformWANHandshake()) { return false; }

	if (client_.IsTLSConnectionEstablished() ) {
		/*
		* Реализовано для совместимости всех версий протокола.
		* 
		*/
		client_.SetIsDataFlag(false, false);
		if (!PerformLANHandshake()) { return false; }
	}

	return true;
}

bool secure_proxy::Proxy::PerformLANHandshake() {
	if (!server_.PerformHandshake()) { return false; }
	server_.SetIsDataFlag();
	
	return true;
}

bool secure_proxy::Proxy::PerformWANHandshake() {
	if (!client_.PerformHandshake()) { return false; }
	client_.SetIsDataFlag();

	return true;
}

bool secure_proxy::Proxy::ProcessApplicationData(unsigned char* message, int message_len, bool is_server) {
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

	// Отправляем на PIN
	// Future Coding
	//
	// Шифрование данных на противоположной стороне для отправки

	if (is_server) { 
		if (!EncryptData(&client_, decrypted_data, decrypted_data_size)) { return false; }
	}
	else { 
		if (!EncryptData(&server_, decrypted_data, decrypted_data_size)) { return false; }
	}

	return true;
}

bool secure_proxy::Proxy::DecryptData(share::Endpoint* role, unsigned char*& buf, int& decrypted) {
	auto readed{ 0 };
	auto read_status_code_resolve{share::ssl_status::SSL_STATUS_OK};
	auto ssl_pending{ 0 };
	auto default_size{ 65536 };
	auto read_chunk_size{ default_size };
	auto bytes_left_to_read{ 0 };

	if (!tools::AllocateMemory(buf, default_size)) { return false; }

	while (true) {
		readed = SSL_read(role->ssl_, buf + decrypted, read_chunk_size);
		if (readed <= 0) { break; }

		decrypted += readed;
		bytes_left_to_read = SSL_pending(role->ssl_);

		if ( bytes_left_to_read > 0) {
			if (!tools::ExpandBuffer(buf, default_size + bytes_left_to_read)) { return false; }
			read_chunk_size = bytes_left_to_read;
		}
	}

	read_status_code_resolve = role->GetSSLStatus(readed);
	if (read_status_code_resolve == share::ssl_status::SSL_STATUS_FAIL) { return false; }

	return true;
}

bool secure_proxy::Proxy::EncryptData(share::Endpoint* role, unsigned char* data, int data_len) {
	int write_status{ 0 };
	int write_status_resolve{ 0 };
	
	write_status = SSL_write(role->ssl_, data, data_len);
	write_status_resolve = role->GetSSLStatus(write_status);
	
	role->SetIsDataFlag();

	if (data) { tools::ClearMemory(data, true); }
	if (write_status_resolve == share::ssl_status::SSL_STATUS_FAIL) { return false; }

	return true;
}
void secure_proxy::Proxy::ResetBIOBuffer(BIO* bio) {
	BIO_reset(bio);
}

bool secure_proxy::Proxy::SetServerName() {
	std::string host_name{};

	host_name = SSL_get_servername(server_.ssl_, TLSEXT_NAMETYPE_host_name);
	return SSL_set_tlsext_host_name(client_.ssl_, host_name.c_str());
}