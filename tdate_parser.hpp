
#ifndef MINI_HTTPD_CPP_TDATE_PARSER_HPP
#define MINI_HTTPD_CPP_TDATE_PARSER_HPP

#pragma once

#include <ctime> // time_t
#include <string_view>
#include <optional>

namespace mini_httpd
{

	std::optional<time_t> tdate_parse(const std::string_view str);
}


#endif // !MINI_HTTPD_CPP_TDATE_PARSER_HPP
