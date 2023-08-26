/*!
* @file
* @brief ��������� ����������� ���������� TLS-����� ������������ ������.
*/
#pragma once

#include <algorithm>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include "tools.h"

namespace fs = std::filesystem;

namespace share {

	namespace ssl_status {
		/// ����� ��������� �������� ���������� �������� � ������ ����������
		enum code {
			SSL_STATUS_WANT_IO, //!< ������/������ ������� ������ ��� ������ ��� ������
			SSL_STATUS_FAIL,    //!< ����������� ������
			SSL_STATUS_OK       //!< �������� ��������� �������
		};

		/// ����� ��������� �������� ��� ������ ������ �� BIO
		enum read {
			READ_STATUS_LEFT_DATA, //!< ��������� �� ��� ������
			READ_STATUS_SUCCESS,   //!< ��� ������ ��������� �������
			READ_STATUS_RETRY,     //!< ���������� ���������� � BIO �����
			READ_STATUS_FAIL       //!< ����������� ������
		};
	}

	namespace server_tools {
		/*!
		* @brief ������������ ��������� ClientHello.
		* @retval 1 ��������� ��������� �������.
		* @retval 0 � �������� ��������� �������� ����������� ������.
		*/
		int ProcessClientHello(SSL*, int*, void*);

		/*!
		* @brief ��������� ������� ���������� SNI
		* @retval true  ���������� ����
		* @retval false ���������� ���
		*/
		bool IsExistsSNI(SSL*, const unsigned char**, size_t*);
		
		/*!
		* @brief ��������� ������ �������� ����� �������.
		* 
		* @retval[in] ����������.
		* 
		* @return ������ ����� �������.
		*/
		int GetLenExtensionValue(const unsigned char*&);
		
		/*!
		* @brief ��������� ������ ���������� � ��������� �������� ��� ����������.
		* 
		* @param[in] ext	 ���������� RFC 3546 / 6066.
		* @param[in] ext_len ������ ����������.
		* 
		* @retval true  ������ ���������� �������.
		* @retval false ������ ���������� �� �������.
		*/
		bool CheckLenExtension(const unsigned char*&, size_t*);

		/*!
		* @brief ��������� ������������ ���� ���������� ���������� SNI.
		* 
		* @param[in] extension ����������.
		* 
		* @retval true  ��� ���������� - ���������� SNI.
		* @retval false ���������� �� �������� SNI.
		*/
		bool CheckTypeExtensionSNI(const unsigned char*&);

		/*!
		* @brief ��������� �������� ����� ������� �� ����������.
		* 
		* @param[in] ext ����������.
		*
		* @return ��� �������.
		*/
		std::string GetSNI(const unsigned char*&);
	}

	/*!
	* @brief ��������� ��������� �������� ������ �������.
	* @details
	* ���������� �������� �� ������������� �������� Singleton. ��� ����������  
	* ���, ��� ��� ������� ���������� ���������� ��������� �������� �����������, ���  
	* ������� ������� ������� CSR. ��� �������� CSR ��������� ����� �������. ���������  
	* ������ �������� ����������������� ���������. ������� ����� ����� ������� ���  
	* ������������� ������ � ������������ ��� ���� ����������.
	*/
	class ServerKeysMaker {

	public:
		ServerKeysMaker(const ServerKeysMaker&) = delete;
		ServerKeysMaker& operator=(const ServerKeysMaker&) = delete;

		/*!
		* @brief ��������� ������ �� ��������(���� �� �������) ������ �������.
		* 
		* @param[in] key_size ������ �����.
		* 
		* @return ���� ������ �������.
		*/
		static EVP_PKEY* Get(int);
	protected:
		/*!
		* @brief ������� ����� �������.
		* 
		* @param[in] key_size ������ �����.
		*	Nothing.
		*/
		explicit ServerKeysMaker(int);

	private:
		EVP_PKEY* pair_keys_; //!< ���� RSA ������ �������.
	};

	/*!
	* @brief ��������� ��������� �������� ������� ������� � CA �� ������ �����������.
	* @details
	* ���������� �������� �� ������������� �������� Singleton. �.�. ������ �������� � ������������ ������,  
	* ��� ������� ������ ���������� ����� ������������ ���� ������ CSR, ������� ������ ���� CN (domain name).  
	* ��������� ���� �������� �����������. ��� �������� ������� � ���������� CA, CSR ������������� ���������  
	* ������ �������, ��� �������� �� �����������. ��������� CA ���������� � ������, ������ �������� ��������� �� �����.  
	* �������� ������� ����� ����� �������������.
	*/
	class ServerCSRTemplateMaker {
	public:
		ServerCSRTemplateMaker(const ServerCSRTemplateMaker&) = delete;
		ServerCSRTemplateMaker& operator=(const ServerCSRTemplateMaker&) = delete;

		/*!
		* @brief ��������� ������ �� ��������(���� �� ������) ������� ������� CSR.
		* @return ������ ������� CSR.
		*/
		static X509_REQ* Get();
	protected:
		/*!
		* @brief ������� � ������������� CSR.
		*	Nothing.
		*/
		ServerCSRTemplateMaker();
	private:
		/*!
		* @brief ��������� ���� � SubjectName CSR.
		* 
		* @retval true  �������� ��������� �������.
		* @retval false ��������� ����������� ������.
		*/
		bool FillSubjectNameFields();

		/*!
		* @brief ��������� ���� � SubjectName CSR.
		* 
		* @param[in, out] subject_name ������ SubjectName �� CSR.
		* @param[in]      field_name   ����������� ����.
		* @param[in]      field_value  �������� ����.
		* 
		* @retval true  ���� ������� ���������.
		* @retval false ��������� ����������� ������.
		*/
		bool AddTxtEntryToSubjectName(X509_NAME*,const std::string&, const std::string&);
		
		/*!
		* @brief ������������� ��������� ���� ������� � CSR.
		* 
		* @retval true  �������� ��������� �������
		* @retval false ��������� ����������� ������
		*/
		bool SetPublicKey();

		X509_REQ* csr_; //!< ������ ������� �� ������ ����������� CSR.
	};

	/*!
	* @brief ��������� ��������� �������� ��������� �������.  
	* @details
	* ���������� �������� �� ������������� �������� Singleton. ��������� ��������, ����� ������ ���������� SSL.  
	* ��� ���� ���������� ��������� ������� Proxy ����� ��������� �� ����������� �����������. API OpenSSL ���������  
	* ��������� ����������, ������������ �������� ����� ���������:
	* * � ��������� ����� ��������� ���������� ������ SSL.
	* * ��������������� � ���������� SSL.
	* ���������� ������� ������ ������������ ������������� ������� 2. ��� ����������� ���, ��� ��������� �������������  
	* ����������� ����������� ����� ��� ���������. ��� ��������� ���������� ���������� SNI, ������������ � ��������� ClientHello.  
	* ��������� ClientHello ����������� � ������� ��������� ������, ������� ���������� SSL_accept. ����� ������� SSL_accrpt ������ SSL
	* ������ ���� ������. �.�. ������ SSL ��������� �� ���� ���������, �� ��������� ���������� ������, � ���������, ��������� �������������  
	* �����������, ����������� ���������������, � ���������� ������. ������� ��� ���� ���������� �������� ������������� ������ ��������� ��� �������.
	*/

	class ServerCTXMaker {
	public:
		ServerCTXMaker(const ServerCTXMaker&) = delete;
		ServerCTXMaker& operator=(const ServerCTXMaker&) = delete;

		/*!
		* @brief ��������� ������ �� �������� (���� �� ������) ��������� ��� �������.
		* 
		* @return �������� �������.
		*/
		static SSL_CTX* Get();
	protected:
		/*!
		* @brief ������� � ������������� �������� �������.
		*	Nothing.
		*/
		ServerCTXMaker();
	private:
		SSL_CTX* ctx_; //!< �������� �������.
	};

	/*!
	* @brief ��������� ��������� �������� ��������� �������.
	* @details
	* ���������� �������� �� ������������� �������� Singleton. � WAN Proxy ��������� ��������. ��� ���� ���������  
	* ��������� ����� ������������. ����������� �������� ���������� SNI ��������� ClientHello. ������� ��� ��������  
	* ���������� ������ SSL ��� ���� ���������� ����� ����������� ���� ��������� ��������� � ������������������
	* �����������. ���������� SNI ����� ��������� � ������ ��������� ��������� SSL.
	*/
	class ClientCTXMaker {
	public:
		ClientCTXMaker(const ClientCTXMaker&) = delete;
		ClientCTXMaker& operator=(const ClientCTXMaker&) = delete;

		/*!
		* @brief ��������� ������ �� �������� (���� �� ������) ��������� ��� �������.
		*
		* @return �������� �������.
		*/
		static SSL_CTX* Get();
	protected:

		/*!
		* @brief ������� � ������������� �������� �������.
		*	Nothing.
		*/
		ClientCTXMaker();
	private:
		SSL_CTX* ctx_; //!< �������� �������.
	};
	
	/*!
	* @brief ��������� ��������� �������� ������ ������������.
	* @details
	* ���������� �������� �� ������������� �������� Singleton. ��� ���� ���������� ����� �����������  
	* ���� ����� ������������.
	*/
	class RootCA {
	public:
		RootCA(const RootCA&) = delete;
		RootCA& operator=(const RootCA&) = delete;

		/*!
		* @brief ���������� ������ �� �������� (���� �� ������) ������ ������������.
		* 
		* @return ��������� �� ��������� ������ ������������.
		*/
		static RootCA* Get();

		/*!
		* @brief ��������� ����������.
		* 
		* @param[in] domain �������� ���
		* 
		* @return ��������� �� ���������� ����������.
		*/
		X509* IssueCertificate(const std::string&);

		/*!
		* @brief ���������� ����������.
		* 
		* @return ����������.
		*/
		X509* GetCertificate() { return certificate_; }

		/*!
		* @brief ���������� IssuerName.
		*
		* @return IssuerName.
		*/
		X509_NAME* GetIssuerName() { return issuer_name_; }

		/*!
		* @brief ���������� ��������� ����.
		*
		* @return ��������� ����.
		*/
		EVP_PKEY* GetPrivateKey() { return private_key_; }

	protected:
		/*!
		* @brief ��������� ���������� � ��������� ���� CA.
		*	Nothing.
		*/
		RootCA();
	private:
		// ��������� �������� ����� � PEM �������
		/*
		* @brief ��������� ���� � PEM-�������.
		* 
		* @tparam ������������ �������� ������� �������� ���������� � PEM-�������.
		* @param[in] pem_file_path ���� � �����.
		* @param[in] load_function ���������� �������.
		* 
		* @return ����������� ���������.
		*/
		template<typename T>
		T LoadPem(const fs::path&, T(*load_function)(FILE*, T*, pem_password_cb*, void*));

		/*!
		* @brief ���������� �������� ����� �����������
		* 
		* @return ��������� �� �������� ����� �����������.
		*/
		unsigned char* GenerateSerialNumber();

		/*!
		* @brief �������� ��� ������� � CSR
		* 
		* @param[in,out] csr    ������ �� ������ �����������.
		* @param[in]     domain �������� ���, ��� �������� ���������� ��������� ����������.
		* 
		* @retval true  ������ ��������� �������
		* @retval false ��������� ����������� ������
		*/
		bool ReplaceCSRDomainName(X509_REQ*, const std::string&);

		/*!
		* @brief ������������� �������� �����.
		* 
		* @param[in, out] property_sn �������� ����� �����������.
		* @param[in]      value �������� ��������� ������.
		* @param[in]      size ������ ��������� ������.
		* 
		* @retval true  �������� ����� �������� �������.
		* @retval false ��������� ����������� ������.
		*/
		bool SetSerialNumber(ASN1_STRING*, unsigned char*, int);
		
		/*!
		* @brief ������������� ���� �������� �����������.
		* 
		* @param[in, out] certificate ����������.
		* 
		* @retval true  ���� �������� ���������� �������.
		* @retval fasle ��������� ����������� ������.
		*/
		bool SetExpirationDate(X509*);

		/*!
		* @brief ������������� �������������� ��� �������.
		* 
		* @param[in, out] certificate ����������.
		* @param[in]      domain �������������� ��� �������.
		* 
		* @retval true  �������������� ��� ����������� �������.
		* @retval false ��������� ����������� ������.
		*/
		bool SetSubjectAltName(X509*, const std::string&);

		/*!
		* @brief ����������� ����������.
		* 
		* @param[in, out] certificate ����������.
		* 
		* @retval true  ���������� �������� �������.
		* @retval false ��������� ����������� ������.
		*/
		bool Sign(X509*);

		X509* certificate_;     //!< ���������� CA. 
		X509_NAME* issuer_name_;//!< ������ � �������� �����������.
		EVP_PKEY* private_key_; //!< ��������� ���� CA.
	};

	/*!
	* @brief ����������� ����� ��������� ����� ��������� ��� ������� � �������.
	*/
	class Endpoint {
	public:
		Endpoint() : input_(nullptr), output_(nullptr), ssl_(nullptr), has_data_(false) {};
		~Endpoint();

		/*!
		* @brief ������� ���������� ��� ����������� � ����������� ���������� ����� (������/������).
		* @retval true  �������� ��������� �������
		* @retval false ��� �������� ��������� ����������� ������
		*/
		bool Load();

		/*!
		* @brief ��������� ��������� ��� ��������� ������������ ����������.
		* @retval true  ��� �������� �������
		* @retval false ��� ���������� ���� ��������� ����������� ������ ��� �������������� ���������  
		* ������� ������� ����������.
		*/
		virtual bool PerformHandshake() = 0;

		/*!
		* @brief ����������, ��� �� ����������� Handshake
		* @retval true  Handshake ��� �����������
		* @retval false Handshake �� ��� �����������
		*/
		bool IsHandshakeInit();

		/*!
		* @brief ���������� ������� ������ ��� ���������� �������� � ����������� SSL.
		* @retval ssl_status::SSL_STATUS_OK      ������ � ������� ���.
		* @retval ssl_status::SSL_STATUS_WANT_IO ��������� �������� �������� ������/������ (�� ������)
		* @retval ssl_status::SSL_STATUS_FAIL    ������
		*/
		enum ssl_status::code GetSSLStatus(int);

		/*!
		* @brief �������� ��������� ���������� � ��������� ������ ��� ������.
		* @param[in] from_bio ��������� ������������ �������� ������ � �������� BIO
		* @param[in] value    �������� ��� ���������, ���� from_bio == false
		*	Nothing.
		*/
		void SetIsDataFlag(bool from_bio=true, bool value=true);

		/*!
		* @brief ��������� ������ �� ������� BIO.
		* 
		* @param[in] data     ������ ��� ����������
		* @param[in] data_len ������ ������
		* 
		* @retval true  ������ ��������� �������.
		* @retval false ��� ���������� ������ ��������� ����������� ������.
		*/
		bool SendToBIOChannel(unsigned char*, int);

		/*!
		* @brief ���������� ��������� TLS-���������
		* @retval true  ���������� ����������� ��� ���������� �������� ������.
		* @retval false ���������� �� ������ ��� ���������� �������� ������.
		*/
		bool IsTLSConnectionEstablished();

		/*!
		* @brief ���������� ������� ������ ��� ������ � �������� �������/�������
		* @retval true  ���� ������ ��� ������
		* @retval false ��� ������ ��� ������
		*/
		bool HasReadData();
		

		/*!
		* @brief ������ ������ ��� �������� �������/�������
		*
		* @param[out] buf      ������� ������, ���� ����� �������� ����������� ������
		* @param[in]  buf_size ������ ������� ������
		* @param[out] readed   ���������� ���������� ����
		* 
		* @retval READ_STATUS_LEFT_DATA - ��������� �� ��� ������. ������� � ��� ��������� ��������  
		* � ������, ���� ������ ������, ����������� ������������� ������ ������� ������, ��������� ��� ������.
		* @retval READ_STATUS_SUCCESS   - ������ ��������� �������. ��������� ������ ���.
		* @retval READ_STATUS_RETRY     - ��������� ��������� ������ �� ������.
		* @retval READ_STATUS_FAIL      - ��� ������ ��������� ������.
		*/
		enum share::ssl_status::read ReadData(unsigned char*, int, int&);

		BIO* input_; //!< ������� ����� BIO
		BIO* output_;//!< �������� ����� BIO
		SSL* ssl_;   //!< �������� �������� � ��������� ����������
	private:
		/*!
		* @brief ������� ��������� SSL � ��������� ��� ������������
		* 
		* @retval true  ��������� ������ � ��������������� �������.
		* @retval false ��������� ����������� ������ ��� �������� ��� ������������ ���������� SSL.
		*/
		virtual bool CreateSSL() = 0;

		/*!
		* @brief ������� ���������� BIO � ��������� �� ����������������
		* 
		* @retval true  �������� � ���������������� ��������� �������.
		* @retval false ��� �������� ��������� ����������� ������.
		*/
		bool CreateBIO();

		/*!
		* @brief ������� ������, ���������� ��� BIO.
		*	Nothing.
		*/
		void ResetBIO();

		/*!
		* @������� ������, ���������� ��� SSL.
		*	Nothing.
		*/
		void ResetSSL();

		bool has_data_;//!< ���� ������� ������ ��� �������� �������/�������
	};
}