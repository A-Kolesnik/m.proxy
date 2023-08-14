// ���������: 
// 1. ������� ������������� ����� ������, ����������� �������� TLS-����������.
// 2. ������� ������ ��������� ������ ����� ������ (������������ ������)
// 3. �������� Proxy, ����������� � ���� ������� � ��������� ���� � � ���� ������� � ���������� ������������ ����.

#pragma once

#include <string>
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
	class Proxy {
	public:
		Proxy(){};
		Proxy(const Proxy&) = delete;
		Proxy(const Proxy&&) = delete;

		Proxy& operator=(const Proxy&) = delete;
		Proxy& operator=(const Proxy&&) = delete;

		// ��������� �������� ����������� ��� ����������� ����������
		// ���������: client/server
		// 
		//
		bool Load();

		Server server_;
		Client client_;
	};
}
