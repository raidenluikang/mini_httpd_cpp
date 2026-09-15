
#ifndef MINI_HTTPD_CPP_TDATE_PARSER_HPP
#define MINI_HTTPD_CPP_TDATE_PARSER_HPP

#pragma once

#include <ctime> // time_t
#include <string_view>
#include <variant>

namespace mini_httpd
{
	enum class date_parse_ec
	{
		ok = 0,
		
		empty_data, // if input is empty
		
		no_year,    // if input does not have year information
		
		no_month,   // if input does not have month information

		no_day,      // if input does not have day information
		
		year_overflow, // if input year (YY or YYYY formatted) have more or less digits. for example  1017  is incorrect data.
		
		day_overflow,  // if day gives incorrectly for example  32 is overflow data, also 0 is incorrect
		
		month_incorrect, // given month Jan, Feb  incorrrectly.
		
		weekday_incorrect, // given week day  Tue, Mon incorrectly. 
		
		hour_overflow, // 0..23   there may be 24 26
		
		minute_overflow, // 0..59  there may be given 77 for example
		
		second_overflow, // 0..59  there may be given 60 for example
		
		unexpected_symbol, // during parsing unexpected symbol

		unexpected_space,  // during parsing unexpected space

		unexpected_end,    // during parsing unexpected input ends.
	};

	std::optional<time_t> tdate_parse(const std::string_view str);
}


#endif // !MINI_HTTPD_CPP_TDATE_PARSER_HPP
