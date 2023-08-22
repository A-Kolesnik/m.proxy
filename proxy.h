// ���������: 
// 1. ������� ������������� ����� ������, ����������� �������� TLS-����������.
// 2. ������� ������ ��������� ������ ����� ������ (������������ ������)
// 3. �������� Proxy, ����������� � ���� ������� � ��������� ���� � � ���� ������� � ���������� ������������ ����.

#pragma once

#include <string>
#include <memory.h>
#include "client.h"
#include "server.h"
#include "config.h"
#include "share.h"

namespace secure_proxy {

	// ��������� ������������ ��� ���� ���������� ��������:
	// 1. ���� ������ �������(public/private)
	// 2. ������ �� ������ ����������� CSR. ����������, � 
	// ������� ���������� ���� ���� - ��� Domain Name, �������
	// ���������� � ���������� ��������� ClientHello SNI (Server Name Indicator)
	// 3. �������� �������
	// 
	// !!! ������ ����� ��������� ���������� ��� ����-������.
	// 
	// ��� �������� ���������� ���� ��������, ������� ���������� true,
	// � ��������� ������, false. 
	// 
	// !!! ���� ��������, ��� � ������ ����� ������ ������������ ������ �� ���� �����.
	// 
	// ���� ��������� ������ ��� ���������� ����� �� �������� ��������,
	// ������, ���������� �� ���������� �����, ���������.
	// ����� ��������� ���������� �������, ��� ������� ������ ���������� ������� 
	// ������� Reset.
	// 
	// ������ �������������:
	// 
	// 1-> if(!secure_proxy::Init()) { exit(1); };
	// 2-> secure_proxy::Reset();
	//
	bool Init();
	void Reset();

	namespace init_tools {
		bool GenerateServerKeys();
		bool GenerateCSRTemplate();
		bool LoadCAKeyData();
		bool LoadCtx();
	}

	namespace reset_tools {
		void ResetServerKeys();
		void ResetCA();
		void ResetCSR();
		void ResetCTX();
	}

	// ���������� �� ��������
	// 
	// ��������� ��������� ���������� ����������.
	// ��������� ������ ��������� ��� ������� ������ ����������.
	// ����� �� ������������ ������������� �������������.
	//
	// ������ �������� ���������� ������:
	// 
	// 1-> secure_proxy::Proxy proxy{};
	// 2-> if(!proxy.Load()){ exit(1); }
	// 
	// 
	// 
	// 
	// 
	// ������� ��� ����������:
	//	- ��������� ������ ������������ ����������� �������� ������� ������ ��� �������� �������/�������
	//	- ����� ������������ ��������� ���� ���������� �������� TLS ����������, ��������� ����� Proxy
	//	  ������������ ������ ������������ ClientHello � �������� ��������������� ���������� (�� ����� 
	//	  ����������, � ��� ����� ������� ����������). ����� �� ��������� ��������� ��� ������������ 
	//	  ���������� �� ������������ LAN ����� ����������� ����� ����, ��� ���������� ����� Proxy ���������
	//    ���������� � �������� � ���������. �������������� ��������� ������� ����� ��������� � BIO.
	//	  ��� ����� � ����� ����, ������� ����� ��������� �� ��, ���� �� ������ ��� �������� �������/�������.
	// API OpenSSL ��� ����������:
	//	1. SSL_in_before(): 1 - Handshake �� ��� ����������� / 0 - Handshake ��� �����������
	//  2. 
	// 
	class Proxy {
	public:
		Proxy() {};
		Proxy(const Proxy&) = delete;
		Proxy(const Proxy&&) = delete;

		Proxy& operator=(const Proxy&) = delete;
		Proxy& operator=(const Proxy&&) = delete;

		// ��������� �������� ����������� ��� ����������� ����������
		// ���������: client/server
		// 

		bool Load();

		//
		bool ProcessLANClientMessage(unsigned char*, int);

		//
		bool ProcessWANServerMessage(unsigned char*, int);

		// Temp
		void Process(unsigned char*&, size_t&);
		//
		Server server_;
		Client client_;

	private:
		//
		bool EstablishLANConnection();
		bool EstablishWANConnection();

		bool PerformLANHandshake();
		bool PerformWANHandshake();

		void ResetBIOBuffer(BIO*);
		
		/*!
		* @brief ������������� ���������� SNI � ���������� ����� Proxy
		* 
		* �������� ��� ���������� ����������� �� ������� SSL ��������� ����� Proxy,
		* ��� ��������������� ����� ��������� ��������� ClientHello. ���� � ���������
		* �� ������� ����� ������������� ���������� SNI, �������� ������������ ����������
		* ����� ��������.
		* 
		* @return 
		*/
		bool SetServerName();

		/*!
		* @brief ��������� ������ ����������
		* 
		* � �������� ��������� ����������� ����������/������������ ������,
		* ����� ����������� ������� ����� ���������� � ��������� ������ ������.
		*/
		bool ProcessApplicationData(unsigned char*, int, bool);
		
		/*!
		* @brief ��������� ������������ ���������
		*/
		bool DecryptData(share::Endpoint*,unsigned char*&, int&);

		/*!
		* @brief ��������� ���������� ������. ��������� ������������� � BIO output
		* 
		*/
		bool EncryptData(share::Endpoint*, unsigned char*, int);
	};
}
