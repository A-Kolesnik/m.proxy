#pragma once

namespace secure_proxy {

	class Client {
		Client() {};
		Client(const Client&) = delete;
		Client(const Client&&) = delete;

		Client& operator=(const Client&) = delete;
		Client& operator=(const Client&&) = delete;
	};
}
