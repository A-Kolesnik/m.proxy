// Описывает пространство имен (в том числе вложенные),
// содержащее переменные для конфигурирования отдельных сущностей.
// Например, пути к файлам сертификата и приватного ключа корневого центра сертификации.

#pragma once

#include <filesystem>

namespace fs = std::filesystem;

namespace default_config {
	namespace ca {
		const fs::path kPathCert{"/home/user/mitm.proxy/MitmProxy/ca/ca2.cer"};
		const fs::path kPathPrivateKey{"/home/user/mitm.proxy/MitmProxy/ca/ca2.key"};
	}

	namespace server {
		const auto kKeySize{ 2048 };
		const auto kValidYears{ 1 };
		const auto kSerialNumberSize{ 20 };

		const std::string kCountryLabel{"C"};
		const std::string kStateLabel{"ST"};
		const std::string kCityLabel{"L"};
		const std::string kOrganizationLabel{"O"};
		const std::string kDomainLabel{"CN"};

		const std::string kCountryValue{ "RU" };
		const std::string kStateValue{ "Moscow" };
		const std::string kCityValue{"Moscow" };
		const std::string kOrganizationValue{ "Team" };
	}
}