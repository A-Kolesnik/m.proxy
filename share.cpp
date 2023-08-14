#include <iostream>
#include "config.h"
#include "share.h"

share::ServerKeysMaker::ServerKeysMaker(int key_size) {
	pair_keys_ = EVP_RSA_gen(key_size);
}


EVP_PKEY* share::ServerKeysMaker::Get(int key_size) {
	static ServerKeysMaker maker{key_size};
	return maker.pair_keys_;
}

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

template<typename T>
T share::RootCA::LoadPem(const fs::path& pem_file_path, T(*load_function)(FILE*, T*, pem_password_cb*, void*)) {
	
	auto mode_read{ "rb" };
	
	auto pem_file_ref = tools::OpenFile(pem_file_path, mode_read);

	if (!pem_file_ref.get()) {
		return nullptr;
	}
	
	return load_function(pem_file_ref.get(), nullptr, nullptr, nullptr);

}

share::RootCA* share::RootCA::Get() {
	static RootCA ca{};
	return &ca;
}

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

bool share::RootCA::SetSerialNumber(ASN1_STRING* property_sn, unsigned char* value, int size) {
	auto status = ASN1_STRING_set(property_sn, value, size);

	delete[] value;
	if (!status) { return false; }

	return true;
}

bool share::RootCA::SetExpirationDate(X509* certificate) {
	auto kSecsYear{ 31536000 };
	namespace config = default_config::server;

	if (!X509_gmtime_adj(X509_get_notBefore(certificate), 0)) { return false; }
	if (!X509_gmtime_adj(X509_get_notAfter(certificate), kSecsYear * config::kValidYears)) { return false; }

	return true;
}

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

bool share::RootCA::Sign(X509* certificate) {
	auto kSizeError{ 0 };

	if (X509_sign(certificate, private_key_, EVP_sha256()) <= kSizeError) {
		long error = ERR_get_error();
		
		if (error != 0) { return false; }
	}

	return true;
}

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

bool share::ServerCSRTemplateMaker::FillSubjectNameFields() {
	
	X509_NAME* subject_name{ nullptr };

	namespace config = default_config::server;

	subject_name = X509_REQ_get_subject_name(csr_);

	if (!AddTxtEntryToSubjectName(subject_name, config::kCountryLabel, config::kCountryValue) or
		!AddTxtEntryToSubjectName(subject_name, config::kStateLabel, config::kStateValue) or
		!AddTxtEntryToSubjectName(subject_name, config::kCityLabel, config::kCityValue) or
		!AddTxtEntryToSubjectName(subject_name, config::kOrganizationLabel, config::kOrganizationValue) or
		//
		!AddTxtEntryToSubjectName(subject_name, config::kDomainLabel, "test")
		) {
		return false;
	}

	return true;
}

bool share::ServerCSRTemplateMaker::AddTxtEntryToSubjectName(X509_NAME* subject_name, const std::string& field_name, 
	const std::string& field_value) {
	return X509_NAME_add_entry_by_txt(subject_name, field_name.c_str(), MBSTRING_ASC, (const unsigned char*)field_value.c_str(), 
		-1, -1, 0);
}

bool share::ServerCSRTemplateMaker::SetPublicKey() {
	EVP_PKEY* server_keys = ServerKeysMaker::Get(default_config::server::kKeySize);

	return X509_REQ_set_pubkey(csr_, server_keys);
}

X509_REQ* share::ServerCSRTemplateMaker::Get() {
	static ServerCSRTemplateMaker maker{};

	return maker.csr_;
}

share::ServerCTXMaker::ServerCTXMaker(): ctx_(nullptr) {
	ctx_ = SSL_CTX_new(TLS_server_method());

	if (!ctx_) { return; }

	SSL_CTX_set_options(ctx_, SSL_OP_ALL);
	
	SSL_CTX_set_client_hello_cb(ctx_, server_tools::ProcessClientHello, nullptr);

}

SSL_CTX* share::ServerCTXMaker::Get() {
	static ServerCTXMaker maker{};
	return maker.ctx_;
}

share::ClientCTXMaker::ClientCTXMaker() {
	ctx_ = SSL_CTX_new(TLS_client_method());

	if (!ctx_) { return; }

	SSL_CTX_set_options(ctx_, SSL_OP_ALL);

	// Добавить пути к хранилищу сертификатов
}

SSL_CTX* share::ClientCTXMaker::Get() {
	static ClientCTXMaker maker{};
	return maker.ctx_;
}

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
	
	//
	// !!! Обрати внимание на функцию. Лучшего способа закастить не нашел
	//

	if (sni = GetSNI(extension); sni.empty()) { return SSL_CLIENT_HELLO_CB; }

	ca = share::RootCA::Get();
	certificate = ca->IssueCertificate(sni);
	pair_keys = share::ServerKeysMaker::Get(default_config::server::kKeySize);

	SSL_use_certificate(ssl, certificate);
	SSL_use_PrivateKey(ssl, pair_keys);

	return SSL_CLIENT_HELLO_SUCCESS;
}

bool share::server_tools::IsExistsSNI(SSL* ssl, const unsigned char** ext, size_t* ext_len) {
	auto is_exists{ 0 };
	auto ext_len_field_size{ 2 };

	is_exists = SSL_client_hello_get0_ext(ssl, TLSEXT_NAMETYPE_host_name, ext, ext_len);

	if (!is_exists || static_cast<int>(*ext_len) <= ext_len_field_size) { return false; }

	return true;
}

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

bool share::server_tools::CheckTypeExtensionSNI(const unsigned char*& extension) {
	if (*extension++ != TLSEXT_NAMETYPE_host_name) { return false; }
	return true;
}

int share::server_tools::GetLenExtensionValue(const unsigned char*& extension) {
	unsigned int len{ 0 };

	len = (*extension++) << 8;
	len |= *extension++;

	return len;
}

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
