#pragma once
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "share.h"

namespace secure_proxy {

	class Client : public share::Endpoint {
	public:
		using Endpoint::Endpoint;

		Client(const Client&) = delete;
		Client(const Client&&) = delete;

		Client& operator=(const Client&) = delete;
		Client& operator=(const Client&&) = delete;

		bool PerformHandshake() override;

	private:
		bool CreateSSL() override;
	};
}
