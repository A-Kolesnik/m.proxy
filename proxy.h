/*!
* @file
* @brief ��������� ������ � ������� ����������� � ������������ TLS-����������
* 
* ���� �������� � ���� �������� ��������� �����������:
*  * ����� Proxy
*  * ������� �������� ������ ����� ������������ ������
*  * ������� ������ ������ ����� ������������ ������
*/

#pragma once

#include <string>
#include <memory.h>
#include "client.h"
#include "server.h"
#include "config.h"
#include "share.h"

namespace secure_proxy {
	/*!
	* @brief ��������� ������������ ��� ���� ���������� ����������.
	* @retval true  �������� ��������� �������.
	* @retval false ��� �������� ��������� ����������� ������.
	*/
	bool Init();

	/*!
	* @brief ����������� ������, ���������� ��� ���� ������������ ����������� ������.
	*	Nothing.
	*/
	void Reset();

	namespace init_tools {

		/*
		* @brief ������� ���� ������ ������� ��� �������� �����������.
		* @retval ����� ������� �������.
		* @retval ��� �������� ������ ��������� ����������� ������.
		*/
		bool GenerateServerKeys();

		/*!
		* @brief ������� ������ ��� ������� �� ������ ����������� CSR.
		* @retval true  ������ ������� ������� ������.
		* @retval false ��� �������� ������� �������� ����������� ������.
		*/
		bool GenerateCSRTemplate();

		/*!
		* @brief �������� ����������� ���������� �������� ������ ������������.
		* @retval true  �������� ����������� ��������� �������
		* @retval false ��� �������� ����������� ��������� ����������� ������
		*/
		bool LoadCAKeyData();
		
		/*!
		* @brief ��������� ��������� ��� ���������� � ��������� ����� Proxy
		* @retval true  ��������� ������������ �������
		* @retval false ��� ������������ ������ �� ���������� ��������� ����������� ������
		*/
		bool LoadCtx();
	}

	namespace reset_tools {
		/*!
		* @brief ����������� ������, ���������� ��� ���� ������ �������.
		*	Nothing.
		*/
		void ResetServerKeys();

		/*!
		* @brief ����������� ������, ���������� ��� ����������� � ���������� ����� CA.
		*	Nothing.
		*/
		void ResetCA();

		/*!
		* @brief ������������ ������, ����������� ��� ������� ������� CSR.
		*	Nothing.
		*/
		void ResetCSR();

		/*!
		* @brief ������������ ������, ���������� ��� ���������� ������� � �������.
		*	Nothing.
		*/
		void ResetCTX();
	}

	/*!
	* @brief ������������ ��������� TLS-����������
	* @details
	* ��������� ������ ��������� ��� ������� ������ ���������� � ��������� � �������� ������� � ��������� ����  
	* � � �������� ������� �� �������. ������������ ��������� ��������� ��������� ���������, � ����� ������   
	* ���������� � ������ ����������. ������ �������� ���������� ������:  
	* @code
	* secure_proxy::Proxy proxy{};
	* if(!proxy.Load()){ exit(1); }
	* @endcode
	*/
	class Proxy {
	public:
		Proxy() {};
		Proxy(const Proxy&) = delete;
		Proxy(const Proxy&&) = delete;

		Proxy& operator=(const Proxy&) = delete;
		Proxy& operator=(const Proxy&&) = delete;

		/*!
		* @brief ��������� �������� ����������� ����������� ������� � �������
		* 
		* @retval true  �������� ��������� �������
		* @retval false ��� �������� �������� ����������� ������
		*/
		bool Load();

		/*!
		* @brief ������������ ��������� ������� ��������� ����
		* 
		* @param[in] message     ��������� �������
		* @param[in] message_len ������ ���������
 		* 
		* @retval true  ��������� ��������� ��������� �������
		* @retval false ��� ��������� ��������� �������� ����������� ������
		*/
		bool ProcessLANClientMessage(unsigned char*, int);

		/*!
		* @brief ������������ ��������� ������� ������� ����
		* 
		* @param[in] message     ��������� �������
		* @param[in] message_len ������ ���������
 		* 
		* @retval true  ��������� ��������� ��������� �������
		* @retval false ��� ��������� ��������� �������� ����������� ������
		*/
		bool ProcessWANServerMessage(unsigned char*, int);

		Server server_;//!< ������������ ����� � ��������� ����
		Client client_;//!< ������������ ����� �� ������� ����

	private:
		/*!
		* @brief ������������� ���������� ������� ��������� ���� � �������� Proxy
		* 
		* @retval true  �������� ��������� �������
		* @retval false �������� �� ���������
		*/
		bool EstablishLANConnection();

		/*!
		* @brief ������������� ���������� Proxy ������� � WAN ��������
		*
		* @retval true  �������� ��������� �������
		* @retval false �������� �� ���������
		*/
		bool EstablishWANConnection();

		/*!
		* @brief ��������� ��������� �������� Handshake ��� ��������� ����� Proxy
		* 
		* @retval true  �������� ��������� �������
		* @retval false �������� �� ���������
		*/
		bool PerformLANHandshake();

		/*!
		* @brief ��������� ��������� �������� Handshake ��� ���������� ����� Proxy
		* 
		* @retval true  �������� ��������� �������
		* @retval false �������� �� ���������
		*/
		bool PerformWANHandshake();

		/*!
		* @brief ���������� ��������� BIO.
		* 
		* @param[in,out] bio ������ BIO
		*	Nothing.
		*/
		void ResetBIOBuffer(BIO*);
		
		/*!
		* @brief ������������� ���������� SNI � ���������� ����� Proxy.
		* 
		* @param[in] sni �������� ��� �������, ������������� ��������
		* 
		* @retval true  ���������� ��������� �������
		* @retval false ���������� �� ���������
		*/
		bool SetSNI(std::string);

		/*!
		* @brief ������������� ��������� ��� ������� � ������������ ����������� � ���������� ����� Proxy.
		* 
		* @param[in] host_name ��������� ��� �������
		* 
		* @retval true  ��������� ��� ������� �����������
		* @retval false ��������� ��� ������� �� �����������
		*/
		bool SetExpectedHostName(std::string);

		/*!
		* @brief ��������� ���������������� ��������� �� ����� ������� ���������� ���������� ����� Proxy.
		* 
		* @retval true  ���������������� ��������� �������
		* @retval false ���������������� �� ���������
		*/
		bool ConfigureClientProxyGivenSNI();

		/*!
		* @brief ������������ ������ ����������.
		* 
		* @param[in] is_server   ������ ����, � ������� ��������� Proxy(������/������)
		* 
		* @retval true  ��������� ��������� ��������� �������
		* @retval false ��������� ������ ���������� ��-�� ����������� ������, ���� �� ������� ����� �� ������.
		*/
		bool ProcessApplicationData(bool);
		
		/*!
		* @brief �������������� ���������.
		* 
		* @param[in]     role      ��������� Client/Server
		* @param[in,out] buf       ������ ��� ������ ��������������� ���������
		* @param[in,out] decrypted ������ ��������������� ��������� 
		* 
		* @retval true  ������������� ��������� �������
		* @retval false ��� ���������� �������� ��������� ����������� ������
		*/
		bool DecryptData(share::Endpoint*,unsigned char*&, int&);

		/*!
		* @brief ������� ������.
		* 
		* @param[in] role     ��������� Client/Server
		* @param[in] data     ������ ��� ����������
		* @param[in] data_len ������ ������ ��� ����������
		* 
		* @retval true  ���������� ��������� �������
		* @retval false ���������� �� ���������
		* 
		*/
		bool EncryptData(share::Endpoint*, unsigned char*, int);
	};
}
