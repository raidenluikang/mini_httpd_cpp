

#include <optional>
#include <numeric> 
#include <algorithm>
#include <array>
#include <span>
#include <string_view>
#include <utility>
#include <type_traits>
#include <cstdint>
#include <limits>
#include <variant>

#include "tdate_parser.hpp"



extern "C"
void TDATE_PARSER_DATE_FORMA_STRING_INCORRECT_(const char* msg) {} //without body.


#define MINI_HTTPD_CPP_DATE_VERIFY(cond, message) TDATE_PARSER_DATE_VERIFY(cond, message)

static constexpr void TDATE_PARSER_DATE_VERIFY(bool cond, const char* msg)
{
	if (!cond)
	{
		TDATE_PARSER_DATE_FORMA_STRING_INCORRECT_(msg); // call runtime function.
	}
}


#if defined(__has_cpp_attribute)
#if __has_cpp_attribute(assume) >= 202207L
#define ASSUME(cond) [[assume(cond)]]
#endif
#endif

#ifndef ASSUME
#if defined(_MSC_VER) && !defined(__clang__)
#define ASSUME(cond)  (void)(0) //__assume(cond)
#elif defined(__clang__)
#define ASSUME(cond) __builtin_assume(cond)
#elif defined(__GNUC__)
#define ASSUME(cond) do { if (!(cond)) __builtin_unreachable(); } while (0)
#else
#define ASSUME(cond) ((void)0)
#endif
#endif


#define DATE_VERIFY(cond, msg)  MINI_HTTPD_CPP_DATE_VERIFY(cond, msg)

namespace
{
	

	template <size_t N>
	consteval size_t total_node_size(const std::array< std::pair< std::string_view, int >, N>& buffer) noexcept
	{
		size_t total = 1; // for root.
		for (const auto& element : buffer)
		{
			total += element.first.size();
		}
		return total;
	}
		
	template <size_t NodeSize>
	class ConstTrie
	{
	public:
		using value_type = std::conditional_t< (NodeSize < std::numeric_limits<std::uint8_t>::max()), std::uint8_t, std::uint16_t>;

		static constexpr value_type NPOS = std::numeric_limits<value_type>::max();

		template <typename T, size_t N>
		constexpr
			explicit
			ConstTrie(const std::array<T, N>& words) noexcept
			: nodes_{}
			, nodeCount_{ 1 } // root
		{
			for (const auto [word, val] : words)
			{
				insert(word, val);
			}
		}

		static constexpr value_type root() noexcept { return 0; }

		constexpr value_type step(const value_type cur, const char c) const noexcept
		{
			const std::uint8_t idx = charIndex(c);
			return nodes_[cur].children[idx];
		}

		constexpr std::optional<int> value(value_type cur) const noexcept
		{
			if (cur == NPOS)
				return std::nullopt;
			const value_type v = nodes_[cur].value;
			if (v == NPOS)
				return std::nullopt;
			return static_cast<int>(v);
		}
		constexpr value_type nodeCount() const noexcept {
			return nodeCount_;
		}

	private:

		static constexpr std::uint8_t charIndex(const char c) noexcept
		{
			DATE_VERIFY((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'), "expected non english letter.");

			return static_cast<std::uint8_t>(
				(c >= 'a' && c <= 'z') ? c - 'a' : c - 'A');
		}

		constexpr void insert(std::string_view word, value_type val)
		{
			value_type cur = 0;
			for (const char c : word)
			{
				const std::uint8_t idx = charIndex(c);
				if (NPOS == nodes_[cur].children[idx])
				{
					nodes_[cur].children[idx] = nodeCount_++;
				}
				cur = nodes_[cur].children[idx];
			}
			nodes_[cur].value = val;
		}

	private:
		struct Node
		{
			std::array<value_type, 26> children;
			value_type value;

			constexpr Node() noexcept
				: children{ {
							NPOS, NPOS, NPOS, NPOS, NPOS,
							NPOS, NPOS, NPOS, NPOS, NPOS,
							NPOS, NPOS, NPOS, NPOS, NPOS,
							NPOS, NPOS, NPOS, NPOS, NPOS,
							NPOS, NPOS, NPOS, NPOS, NPOS,
							NPOS
					} }
				, value{ NPOS }
			{
			}
		};

		static_assert(Node().children.back() == NPOS);

		std::array<Node, NodeSize> nodes_;

		value_type nodeCount_; // exists only root.

	};

	constexpr size_t WDAY_SIZE = 2 * 7; // 7 weekdays , short, and long version, so multiplied by 2.
	
	using WDayArray = std::array< std::pair<std::string_view, int>, WDAY_SIZE>;

	using namespace std::literals::string_view_literals;

	consteval WDayArray wday_tab() noexcept {
		return WDayArray{
			{
				{ "sun"sv, 0 }, { "sunday"sv, 0 },
				{ "mon"sv, 1 }, { "monday"sv, 1 },
				{ "tue"sv, 2 }, { "tuesday"sv, 2 },
				{ "wed"sv, 3 }, { "wednesday"sv, 3 },
				{ "thu"sv, 4 }, { "thursday"sv, 4 },
				{ "fri"sv, 5 }, { "friday"sv, 5 },
				{ "sat"sv, 6 }, { "saturday"sv, 6 },
			}
		};
	}


	constexpr size_t node_size_wday = total_node_size( wday_tab() );
	constexpr ConstTrie<node_size_wday> trie_wday( wday_tab() );

	constexpr size_t MON_SIZE = 12 * 2 - 1; // 12 months, and 2 version: short, long, except 'may' which has only long version.

	using MonTabArray = std::array<std::pair<std::string_view, int>, MON_SIZE>;

	consteval MonTabArray mon_tab() noexcept {
		return MonTabArray{
			{
				{ "jan"sv, 0 }, { "january"sv, 0 },
				{ "feb"sv, 1 }, { "february"sv, 1 },
				{ "mar"sv, 2 }, { "march"sv, 2 },
				{ "apr"sv, 3 }, { "april"sv, 3 },
				{ "may"sv, 4 },
				{ "jun"sv, 5 }, { "june"sv, 5 },
				{ "jul"sv, 6 }, { "july"sv, 6 },
				{ "aug"sv, 7 }, { "august"sv, 7 },
				{ "sep"sv, 8 }, { "september"sv, 8 },
				{ "oct"sv, 9 }, { "october"sv, 9 },
				{ "nov"sv, 10 }, { "november"sv, 10 },
				{ "dec"sv, 11 }, { "december"sv, 11 },
			}
		};
	}

	constexpr size_t node_size_mon = total_node_size( mon_tab() );
	constexpr ConstTrie<node_size_mon> trie_mon( mon_tab() );


	template<int min_, int max_, int init_ >
	struct segment
	{
		int value = init_;

		static constexpr inline int MIN_ = min_, MAX_ = max_, INIT_ = init_;
		
		static_assert(min_ <= max_);

		constexpr int set(const int new_value) noexcept {
			if (new_value >= min_ && new_value <= max_) {
				value = new_value;
				return true;
			}
			return false;
		}

		constexpr bool valid() const noexcept
		{
			return (value >= MIN_ && value <= MAX_);
		}
	};
	
	
	struct DateFormatString
	{
		const std::string_view fmt_;

		static constexpr bool is_ascii_letter(char c) noexcept
		{
			return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
		}

		consteval DateFormatString(const std::string_view fmt) noexcept
			:fmt_(fmt) {
			
			const char* start = fmt.data();
			const char* const end = fmt.data() + fmt.size();
			const char* const begin = fmt.data();

			DATE_VERIFY(!fmt.empty(), "EMPTY FORMAT");

			DATE_VERIFY((fmt.front() != ' ' && fmt.front() != '\t'), "FORMAT has leading spaces");

			DATE_VERIFY((fmt.back() != ' ' && fmt.back() != '\t'), "FORMAT has trailing spaces");

			bool has_gmt = false;
			bool has_dd = false;
			bool has_y4 = false;
			bool has_y2 = false;
			bool has_hh = false;
			bool has_mm = false;
			bool has_ss = false;
			bool has_mth = false;
			bool has_wdy = false;

			while (start < end) 
			{
				const char c = *start++;
				switch (c)
				{
				case ' ':
				case '\t':
					//spaces should be ignored
					break;
				
				case '-':
				case ':':
				case ',':
					//separators, skip it.
					break;
				case 'G':
				{
					//may be GMT
					DATE_VERIFY((start + 1 < end && start[0] == 'M' && start[1] == 'T'), "GMT expected");
					
					DATE_VERIFY(!has_gmt, "FORMAT has more one GMT");
					has_gmt = true;

					start += 2;
				}	
				break;
				case 'D':
				{
					//MUST be 'DD'
					DATE_VERIFY((start < end && *start == 'D'), "single D found.");
					DATE_VERIFY(!has_dd, "more one DD found.");
					has_dd = true;
					start += 1;
				}
				break;

				case 'Y':
				{
					//MUST be eighter YY or YYYY
					if (start + 2 < end && start[0] == 'Y' && start[1] == 'Y' && start[2] == 'Y') {
						DATE_VERIFY(!has_y4, "MORE one YYYY found");
						DATE_VERIFY(!has_y2, "ALREADY found YY previously.");
						has_y4 = true;
						
						start += 3;
					}
					else if (start < end && start[0] == 'Y') {
						DATE_VERIFY(!has_y2, "MORE one YY found");
						DATE_VERIFY(!has_y4, "ALREADY found YYYY previously.");
						has_y2 = true;
						
						start += 1;
					}
					else {
						DATE_VERIFY(false, "Incorrect format Y");
					}
				}
				break;

				case 'H':
				{
					//MUST be HH
					DATE_VERIFY(start < end && start[0] == 'H', "Incorrect H format found");
					DATE_VERIFY(!has_hh, "Multiple HH found");
					has_hh = true;
					
					start += 1;
				}
				break;

				case 'M':
				{
					//must be MM
					DATE_VERIFY(start  < end && start[0] == 'M', "Incorrect M format found");
					DATE_VERIFY(!has_mm, "Multiple MM found");
					has_mm = true;

					start += 1;
				}
				break;

				case 'S':
				{
					//This may be SPD format
					if (start + 1 < end && start[0] == 'P' && start[1] == 'D') {
						DATE_VERIFY(!has_dd, "more one DD (or SPD) found.");
						has_dd = true;
						start += 2;
					}
					else 
					{
						//must be 'SS'
						DATE_VERIFY(start < end && start[0] == 'S', "Incorrect S format found");
						DATE_VERIFY(!has_ss, "Multiple SS found");
						has_ss = true;

						start += 1;
					}
				}
				break;

				case 'm':
				{
					// may be mth
					if (start + 1 < end && start[0] == 't' && start[1] == 'h') {
						
						ptrdiff_t ix = start - begin; // it indicated the 't' letter, need check start[-2]
						
						bool previous_sep = (ix < 2) || !is_ascii_letter(begin[ix - 2]);
						bool next_sep = (start + 2 == end) || !is_ascii_letter(start[2]);
						
						//skip  for example:  'ssmth'  'lemth' wods
						if (previous_sep && next_sep) 
						{
							DATE_VERIFY(!has_mth, "Multiple mth found");
							has_mth = true;
							start += 2;
						}
						else {
							//ignore this is part of word, not a single word.
						}
					}
					else {
						//ignore this symbol
					}
				}
				break;

				case 'w':
				{
					// may be wdy
					if (start + 2 < end && start[0] == 'd' && start[1] == 'y') 
					{
						ptrdiff_t ix = start - begin; // it indicated the 't' letter, need check start[-2]

						bool previous_sep = (ix < 2) || !is_ascii_letter(begin[ix - 2]);
						bool next_sep = (start + 2 == end) || !is_ascii_letter(start[2]);

						//skip  for example:  'nowdy'  'wdyies' wods
						if (previous_sep && next_sep)
						{
							DATE_VERIFY(!has_wdy, "Multiple wdy found");
							has_wdy = true;
							start += 2;
						}
						else {
							//ignore this is part of word, not a single word.
						}
					}
				}
				break;

				case '\\':
				{
					DATE_VERIFY(start < end, "after \\ symbol nothing found");
					start += 1; // skip next symbol.
				}
				break;


				default:
					//other symbols should be compile error.
					DATE_VERIFY(false, "incorrect symbol");
					break;
				}//end switch
			}//end while

			DATE_VERIFY(has_dd, "DD format not found");
			DATE_VERIFY(has_mth, "mth format not found");
			DATE_VERIFY(has_y2 || has_y4, "YY or YYYY format not found");

			// HH  MM  SS  wdy - these are optional formats.
		} //end DateFormatString constructor.
	};

	 


	struct TParsedDate
	{
		using TDay    = segment<1, 31, 0 >  ;
		using TMonth  = segment<0, 11, 0 >  ;
		using TYear_2 = segment<0, 99, 0 >  ;
		using TYear_4 = segment<1900, 9999, 0> ;

		
		using TYear = std::variant< TYear_2, TYear_4 > ;

		using THour = segment< 0, 23,  0 > ; //There init_ = 0 because, if format not required hour, 0 is used.
		using TMin  = segment< 0, 59,  0 > ;// same as 0 is default value
		using TSec  = segment< 0, 59,  0 > ; // same as 0 is default value

		using TWDay = segment<0, 6, -1>;

		TDay day;
		TMonth month;
		TYear year;
		THour hour;
		TMin min;
		TSec sec;

		TWDay wday;


		static constexpr bool is_ascii_digit(const char c) noexcept
		{
			return c >= '0' && c <= '9';
		}
		
		static constexpr bool is_ascii_letter(const char c) noexcept
		{
			return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
		}

		static constexpr std::optional<TDay> parseSPDay(std::string_view& str) {
			TDay day;
			//SPD format
			if (str.length() < 2) {
				return std::nullopt;
			}
			const char dig_1 = str[0];
			const char dig_2 = str[1];

			if (is_ascii_digit(dig_1) && is_ascii_digit(dig_2)) {
				const int value = (dig_1 - '0') * 10 + (dig_2 - '0');

				if (day.set(value)) {
					str.remove_prefix(2);
					return day;
				}

				return std::nullopt;
			}

			if ((dig_1 == ' ' || dig_1 == '\t') && is_ascii_digit(dig_2)) {
				const int value = dig_2 - '0';
				if (day.set(value)) {
					str.remove_prefix(2);
					return day;
				}
			}
			return std::nullopt;

		}
		static constexpr std::optional<TDay> parseDay(std::string_view& str)
		{
			TDay day; //auto initialized 0


			//format 'DD'  two digits
			if (str.length() < 2) {
				return std::nullopt;
			}

			
			const char dig_1 = str[0];
			const char dig_2 = str[1];

			if (is_ascii_digit(dig_1) && is_ascii_digit(dig_2)) {
				const int value = (dig_1 - '0') * 10 + (dig_2 - '0');

				if (day.set(value)) {
					str.remove_prefix(2);
					return day;
				}

				return std::nullopt;
			}


			//can't parse or digits is not valid.
			return std::nullopt;
		}

		static constexpr std::optional<TMonth> parseMonth(std::string_view& str)
		{
			TMonth month;

			using Trie = std::remove_cv_t<decltype(trie_mon)>;

			//format 'mth'
			Trie::value_type node = trie_mon.root();
			size_t ix = 0;
			while (ix < str.size() && is_ascii_letter(str[ix])) 
			{
				node = trie_mon.step(node, str[ix]);

				if (node == Trie::NPOS) {
					//can't go
					return std::nullopt;
				}

				ix++;
			}

			
			const std::optional<int> value = trie_mon.value(node);
			
			if (!value.has_value()) 
			{
				return std::nullopt;
			}

			if (!month.set(*value)) 
			{
				return std::nullopt;
			}

			//month is valid now.

			str.remove_prefix(ix);

			return month;
		}

		static constexpr std::optional<TYear_2> parseYear2(std::string_view& str)
		{
			TYear_2 year2;

			// 'YY' format
			if (str.length() < 2) {
				return std::nullopt;
			}

			 
			const char dig_1 = str[0];
			const char dig_2 = str[1];

			if (is_ascii_digit(dig_1) && is_ascii_digit(dig_2)) {
				const int value = (dig_1 - '0') * 10 + (dig_2 - '0');

				if (year2.set(value)) {
					str.remove_prefix(2);
					return year2;
				}
			}

			//can't parse or digits is not valid.
			return std::nullopt;

		}

		static constexpr std::optional<TYear_4> parseYear4(std::string_view& str)
		{
			TYear_4 year4;

			// 'YYYY' format
			if (str.length() < 4) 
			{
				return std::nullopt;
			}


			const char dig_1 = str[0];
			const char dig_2 = str[1];
			const char dig_3 = str[2];
			const char dig_4 = str[3];

			if (is_ascii_digit(dig_1) && 
				is_ascii_digit(dig_2) &&
				is_ascii_digit(dig_3) &&
				is_ascii_digit(dig_4)
				) {
				const int value = (dig_1 - '0') * 1000 + (dig_2 - '0')*100 + (dig_3 - '0') * 10 + (dig_4 - '0') * 1;

				if (year4.set(value)) {
					str.remove_prefix(4);
					return year4;
				}
			}

			//can't parse or digits is not valid.
			return std::nullopt;
		}

		// Hour , min, sec;  HH  MM  SS
		static constexpr std::optional<THour> parseHour(std::string_view& str) {
			THour hour;
			// 'HH' format
			if (str.length() < 2) {
				return std::nullopt;
			}


			const char dig_1 = str[0];
			const char dig_2 = str[1];

			if (is_ascii_digit(dig_1) && is_ascii_digit(dig_2)) {
				const int value = (dig_1 - '0') * 10 + (dig_2 - '0');

				if (hour.set(value)) {
					str.remove_prefix(2);
					return hour;
				}
			}

			//can't parse or digits is not valid.
			return std::nullopt;
		}

		static constexpr std::optional<TMin> parseMinute(std::string_view& str) {
			TMin minute;
			// 'MM' format
			if (str.length() < 2) {
				return std::nullopt;
			}


			const char dig_1 = str[0];
			const char dig_2 = str[1];

			if (is_ascii_digit(dig_1) && is_ascii_digit(dig_2)) {
				const int value = (dig_1 - '0') * 10 + (dig_2 - '0');

				if (minute.set(value)) {
					str.remove_prefix(2);
					return minute;
				}
			}

			//can't parse or digits is not valid.
			return std::nullopt;
		}

		static constexpr std::optional<TSec> parseSecond(std::string_view& str) {
			TSec sec;
			// 'MM' format
			if (str.length() < 2) {
				return std::nullopt;
			}


			const char dig_1 = str[0];
			const char dig_2 = str[1];

			if (is_ascii_digit(dig_1) && is_ascii_digit(dig_2)) {
				const int value = (dig_1 - '0') * 10 + (dig_2 - '0');

				if (sec.set(value)) {
					str.remove_prefix(2);
					return sec;
				}
			}
			//can't parse or digits is not valid.
			return std::nullopt;
		}

		static constexpr std::optional<TWDay> parseWeekday(std::string_view& str)
		{
			TWDay wday;

			using Trie = std::remove_cv_t<decltype(trie_wday)>;

			//format 'mth'
			Trie::value_type node = trie_wday.root();
			size_t ix = 0;
			while (ix < str.size() && is_ascii_letter(str[ix]))
			{
				node = trie_wday.step(node, str[ix]);

				if (node == Trie::NPOS) {
					//can't go
					return std::nullopt;
				}

				ix++;
			}


			const std::optional<int> value = trie_wday.value(node);

			if (!value.has_value())
			{
				return std::nullopt;
			}

			if (!wday.set(*value))
			{
				return std::nullopt;
			}

			//month is valid now.

			str.remove_prefix(ix);

			return wday;
		}



		static constexpr std::optional<TParsedDate> parseDate(DateFormatString formatString, std::string_view str)
		{
			std::optional<TDay> day;
			std::optional<TMonth> month;
			std::optional<TYear_2> year2;
			std::optional<TYear_4> year4;

			std::optional<THour> hour;
			std::optional<TMin> minute;
			std::optional<TSec> second;

			std::optional<TWDay> wday;
			bool has_gmt = false;
			
			const std::string_view format = formatString.fmt_;
			
			while (!str.empty() && (str.front() == ' ' || str.front() == '\t'))
			{
				str.remove_prefix(1);
			}

			const char* start_fmt = format.data();
			const char* const end_fmt = format.data() + format.size();
			const char* const begin_fmt = format.data();

			while (start_fmt < end_fmt)
			{
				const char symbol = *start_fmt++;

				switch (symbol)
				{
				case ' ':
				case '\t':
					//spaces should be ignored
				{
					const bool has_space = !str.empty() && (str.front() == ' ' || str.front() == '\t');
					if (!has_space) 
					{
						return std::nullopt;
					}
					str.remove_prefix(1);
				}
				break;
				
				case '-':
				case ':':
				case ',':
				{
					if (!str.starts_with(symbol)) {
						return std::nullopt;
					}
					str.remove_prefix(1);
				}
				break;
				case 'G':
				{
					//MUST be GMT
					ASSUME(start_fmt + 1 < end_fmt && start_fmt[0] == 'M' && start_fmt[1] == 'T');
				
					// MUST Be GMT there 
					if (!str.starts_with("GMT"sv)) 
					{
						return std::nullopt;
					}

					//DATE_VERIFY(!has_gmt, "FORMAT has more one GMT");
					ASSUME(!has_gmt);
					has_gmt = true;
					
					start_fmt += 2;
					str.remove_prefix(3); // GMT 
				}
				break;
				case 'D':
				{
					//MUST be 'DD'
					//DATE_VERIFY((start < end && *start == 'D'), "single D found.");
					//DATE_VERIFY(!has_dd, "more one DD found.");
					//has_dd = true;
					
					ASSUME(start_fmt < end_fmt);
					ASSUME(!day.has_value());
					
					day = parseDay(str);
					
					if (!day.has_value()) 
					{
						return std::nullopt;
					}
					
					start_fmt += 1;
				}
				break;

				case 'Y':
				{
					//MUST be eighter YY or YYYY
					if (start_fmt + 2 < end_fmt && start_fmt[0] == 'Y' && start_fmt[1] == 'Y' && start_fmt[2] == 'Y') 
					{
						//DATE_VERIFY(!has_y4, "MORE one YYYY found");
						//DATE_VERIFY(!has_y2, "ALREADY found YY previously.");
						//has_y4 = true;
						
						ASSUME(!year2.has_value() && !year4.has_value());

						year4 = parseYear4(str);
						if (!year4.has_value()) 
						{
							return std::nullopt;
						}
						
						start_fmt += 3;
					}
					else if (start_fmt < end_fmt && start_fmt[0] == 'Y') 
					{
						//DATE_VERIFY(!has_y2, "MORE one YY found");
						//DATE_VERIFY(!has_y4, "ALREADY found YYYY previously.");
						//has_y2 = true;
						ASSUME(!year2.has_value() && !year4.has_value());

						year2 = parseYear2(str);

						if (!year2.has_value()) 
						{
							return std::nullopt;
						}

						start_fmt += 1;
					}
					else {
						ASSUME(false);
					}
				}
				break;

				case 'H':
				{
					//MUST be HH
					//DATE_VERIFY(start < end && start[0] == 'H', "Incorrect H format found");
					//DATE_VERIFY(!has_hh, "Multiple HH found");
					//has_hh = true;
					
					ASSUME(start_fmt < end_fmt);
					
					ASSUME(!hour.has_value());
					
					hour = parseHour(str);

					if (!hour.has_value()) 
					{
						return std::nullopt;
					}

					start_fmt += 1;
				}
				break;

				case 'M':
				{
					//must be MM
					//DATE_VERIFY(start < end && start[0] == 'M', "Incorrect M format found");
					//DATE_VERIFY(!has_mm, "Multiple MM found");
					//has_mm = true;
					ASSUME(start_fmt < end_fmt);
					ASSUME(!minute.has_value());

					minute = parseMinute(str);
					if (!minute.has_value()) 
					{
						return std::nullopt;
					}
					
					start_fmt += 1;
				}
				break;

				case 'S':
				{
					if (start_fmt + 1 < end_fmt && start_fmt[0] == 'P' && start_fmt[1] == 'D') {
						// SPD format
						ASSUME(!day.has_value());
						day = parseSPDay(str);
						if (!day.has_value()) {
							return std::nullopt;
						}

						start_fmt += 2;
					}
					else {
						//must be 'SS'
						//DATE_VERIFY(start < end && start[0] == 'S', "Incorrect S format found");
						//DATE_VERIFY(!has_ss, "Multiple SS found");
						//has_ss = true;

						ASSUME(start_fmt < end_fmt);
						ASSUME(!second.has_value());

						second = parseSecond(str);

						if (!second.has_value())
						{
							return std::nullopt;
						}

						start_fmt += 1;
					}
				}
				break;

				case 'm':
				{
					// may be mth
					if (start_fmt + 1 < end_fmt && start_fmt[0] == 't' && start_fmt[1] == 'h') {

						ptrdiff_t ix = start_fmt - begin_fmt; // it indicated the 't' letter, need check start[-2]

						bool previous_sep = (ix < 2) || !is_ascii_letter(begin_fmt[ix - 2]);
						bool next_sep = (start_fmt + 2 == end_fmt) || !is_ascii_letter(start_fmt[2]);

						//skip  for example:  'ssmth'  'lemth' wods
						if (previous_sep && next_sep)
						{
							//DATE_VERIFY(!has_mth, "Multiple mth found");
							//has_mth = true;
							ASSUME(!month.has_value());

							month = parseMonth(str);

							if (!month.has_value()) {
								return std::nullopt;
							}
							start_fmt += 2;
						}
						else 
						{
							//process 'm' as letter.
							if (!str.starts_with('m')) {
								return std::nullopt;
								
							}
							str.remove_prefix(1);
						}
					}
					else {
						//process 'm' as letter.
						if (!str.starts_with('m')) {
							return std::nullopt;
							
						}
						str.remove_prefix(1);
					}
				}
				break;

				case 'w':
				{
					// may be wdy
					if (start_fmt + 2 < end_fmt && start_fmt[0] == 'd' && start_fmt[1] == 'y')
					{
						ptrdiff_t ix = start_fmt - begin_fmt; // it indicated the 't' letter, need check start[-2]

						bool previous_sep = (ix < 2) || !is_ascii_letter(begin_fmt[ix - 2]);
						bool next_sep = (start_fmt + 2 == end_fmt) || !is_ascii_letter(start_fmt[2]);

						//skip  for example:  'nowdy'  'wdyies' wods
						if (previous_sep && next_sep)
						{
							//DATE_VERIFY(!has_wdy, "Multiple wdy found");
							//has_wdy = true;
							ASSUME(!wday.has_value());
							wday = parseWeekday(str);

							if (!wday.has_value()) {
								return std::nullopt;
							}

							start_fmt += 2;
						}
						else {
							//parse 'w' as letter
							if (!str.starts_with('w')) {
								return std::nullopt;

							}
							str.remove_prefix(1);
						}
					}
					else {
						//parse 'w' as letter
						if (!str.starts_with('w')) {
							return std::nullopt;

						}
						str.remove_prefix(1);
					}

					
				}
				break;

				case '\\':
				{
					//DATE_VERIFY(start < end, "after \\ symbol nothing found");
					ASSUME(start_fmt < end_fmt);

					char next_symbol = *start_fmt++;
					
					if (!str.starts_with(next_symbol)) {
						return std::nullopt;
					}
					str.remove_prefix(1);
				}
				break;


				default:
				{
					ASSUME(false);
				}
				break;
				}//end switch
			}
			

			if (!day.has_value() || !month.has_value()) {
				return std::nullopt;//month and day are required parameters.
			}

			TYear year_s;

			if (year2.has_value()) {
				year_s = *year2;
			}
			else if (year4.has_value()) {
				year_s = *year4;
			}
			else {
				return std::nullopt;//year is required parameter.
				//result.year = TYear_4{ 1900 } ;//default is 1900 year.
			}

			if (day->value > get_month_days(month->value, get_full_year(year_s)))
			{
				//day is incorrect
				return std::nullopt;
			}


			TParsedDate result;
			
			result.year = year_s;
			
			result.day = *day;

			result.month = *month;

			result.hour = hour.value_or(THour{});
			result.min = minute.value_or(TMin{});
			result.sec = second.value_or(TSec{});
			result.wday = wday.value_or(TWDay{});
			
			return result;
		}
		
		static constexpr int get_month_days(int month, int year) noexcept
		{
			ASSUME(month >= 0 && month <= 11);
			ASSUME(year >= 0);
			constexpr int MONTH_DAYS[2][12] =
			{
				//  0,   1,  2,   3,   4,   5,   6,   7,   8,   9,   10, 11
				{   31,  28, 31,  30,  31,  30,  31,  31,  30,  31,  30, 31 },
				{   31,  29, 31,  30,  31,  30,  31,  31,  30,  31,  30, 31 },
			};
			return MONTH_DAYS[is_leap(year)][month];
		}


		static constexpr bool is_leap(const int year) noexcept
		{
			ASSUME(year >= 0);

			if (year % 400 == 0)
			{
				//2400 is leap
				return true;
			}

			if (year % 100 == 0) {
				// 2100 2200 2300 years is not a leap 
				return false;
			}

			//2020, 2024, is leap. 
			return year % 4 == 0;

			//return year % 400 ? (year % 100 ? (year % 4 ? 0 : 1) : 0) : 1;
		}

		static constexpr int get_full_year(const TYear year) noexcept
		{
			struct visitor_year final
			{
				constexpr int operator()(const TYear_2 year2) const noexcept
				{
					ASSUME(year2.value >= 0);
					return year2.value + (year2.value < 70 ? 2000 : 1900);
				}

				constexpr int operator()(const TYear_4 year4) const noexcept
				{
					return year4.value;
				}
			};
			return std::visit(visitor_year{}, year);
		}


		
		// Число високосных лет в диапазоне [1, y] (proleptic Gregorian).
		static constexpr int leap_count(int y) noexcept
		{
			ASSUME(y >= 0);
			return y / 4 - y / 100 + y / 400;
		}

		static constexpr int EPOCH_YEAR = 1970;
		static constexpr int DAYS_IN_YEAR = 365;

		struct MonthIndexes
		{
			static constexpr int JANUAR = 0,
				FEBRUAR = 1,
				MARTH = 2,
				APREL = 3,
				MAY = 4,
				JUNE = 5,
				JULE = 6,
				AUGUST = 7,
				SEPTEMBER = 8,
				OCTOBER = 9,
				NOVEMBER = 10,
				DECEMBER = 11;
		};

		static constexpr int leap_days_since_epoch(const int year) noexcept
		{
			ASSUME(year >= 0 && year <= 9999);
			
			if (year < EPOCH_YEAR) [[unlikely]]
				return 0;
		
			constexpr int LEAP_COUNT_EPOCH = leap_count(EPOCH_YEAR - 1);
			// Считаем количество високосных лет СТРОГО ДО year (т.е. в [EPOCH_YEAR, year - 1]),
			// потому что сам високосный день текущего года учитывается отдельно
			// в to_time() через is_leap(full_year) && month >= 2.
			return leap_count(year - 1) - LEAP_COUNT_EPOCH;
		}

		constexpr time_t to_time() const noexcept
		{

			const int full_year = get_full_year(this->year);
			
			constexpr int monthtab[ 12 ] =
			{
				0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
			};

			/* Years since epoch, converted to days. */
			time_t t = (full_year - EPOCH_YEAR) * DAYS_IN_YEAR;

			/* Leap days for previous years. */
			t += leap_days_since_epoch(full_year);

			/* Days for the beginning of this month. */
			t += monthtab[this->month.value];

			/* Leap day for this year. */
			if (this->month.value >= MonthIndexes::MARTH && is_leap(full_year))
			{
				++t;
			}

			/* Days since the beginning of this month. */
			t += this->day.value - 1;	/* 1-based field */

			/* Hours, minutes, and seconds. */
			t = t * 24 + this->hour.value;
			t = t * 60 + this->min.value;
			t = t * 60 + this->sec.value;

			return t;
		}

		static constexpr std::optional<time_t> parseDateToTime(DateFormatString formatString, std::string_view str) {
			const auto date = parseDate(formatString, str);
			if (date.has_value()) {
				return date->to_time(); 
			}
			else {
				return std::nullopt;
			}
		}

	};
	
	// Массив всех поддерживаемых форматов
	constexpr DateFormatString formats[] =
	{
		"DD-mth-YY HH:MM:SS GMT"sv,
		"DD mth YY HH:MM:SS GMT"sv,
		"HH:MM:SS GMT DD-mth-YY"sv,
		"HH:MM:SS GMT DD mth YY"sv,
		"wdy, DD-mth-YY HH:MM:SS GMT"sv,
		"wdy, DD mth YY HH:MM:SS GMT"sv,
		"wdy mth DD HH:MM:SS GMT YY"sv,
		"wdy mth SPD HH:MM:SS GMT YY"sv
	};

	constexpr std::optional<time_t> tdate_parse_impl(std::string_view str)
	{
		for (const auto fmt : formats) 
		{
			if (const auto date = TParsedDate::parseDateToTime(fmt, str); date.has_value()) 
			{
				return date; // return as optional.
			}
		}

		return std::nullopt;
	}

} // anonymous namespace

std::optional<time_t> mini_httpd::tdate_parse(const std::string_view str)
{
	return tdate_parse_impl(str);
}



#if 0

#include <chrono>
#include <cstdio>
#include "tdate_parser_orig.h"


int main() {
//	DateFormatString  fmt("DD-mth-YY HH:MM:SS GMT"sv);
	const char* str1 =  "Sun Nov  61 08:49:37 GMT 94";
	auto t1 = TParsedDate::parseDate("wdy mth SPD HH:MM:SS GMT YY"sv, str1);
	if (t1.has_value()) {
		std::printf("t1: %lld\n", t1->to_time());
	}
	else {
		std::printf("str1 not parsed\n");
	}


	struct DateTestCase
	{
		std::string_view input;
		std::string_view fmt;
		std::optional<time_t> expected;
	};

	constexpr DateTestCase test_cases[] = {
		{"06-Nov-94 08:49:37 GMT"sv,              "DD-mth-YY HH:MM:SS GMT"sv,       784111777},
		{"20-Jul-69 12:00:00 GMT"sv,              "DD-mth-YY HH:MM:SS GMT"sv,       3141547200},
		{"29 Feb 00 00:00:00 GMT"sv,              "DD mth YY HH:MM:SS GMT"sv,       951782400},
		{"19 Jan 38 03:14:07 GMT"sv,              "DD mth YY HH:MM:SS GMT"sv,       2147483647},
		{"23:59:59 GMT 31-Dec-99"sv,          "HH:MM:SS GMT DD-mth-YY"sv,   946684799},
		{"15:30:00 GMT 04-Jul-23"sv,          "HH:MM:SS GMT DD-mth-YY"sv,   1688484600},
		{"12:00:00 GMT 29 Feb 04"sv,              "HH:MM:SS GMT DD mth YY"sv,       1078056000},
		{"00:00:00 GMT 01 Jan 70"sv,              "HH:MM:SS GMT DD mth YY"sv,       0},
		{"Sunday, 06-Nov-94 08:49:37 GMT"sv,      "wdy, DD-mth-YY HH:MM:SS GMT"sv,  784111777},
		{"Tuesday, 04 Jul 23 15:30:00 GMT"sv,     "wdy, DD mth YY HH:MM:SS GMT"sv,  1688484600},
		{"Thu Jan 01 00:00:00 GMT 70"sv,          "wdy mth DD HH:MM:SS GMT YY"sv,   0},
		{"Sun Nov  6 08:49:37 GMT 94"sv,          "wdy mth  DD HH:MM:SS GMT YY"sv,   784111777},

		// невалидные
		{"32-Nov-94 08:49:37 GMT"sv,   "DD-mth-YY HH:MM:SS GMT"sv, std::nullopt},
		{"06-Nvo-94 08:49:37 GMT"sv,   "DD-mth-YY HH:MM:SS GMT"sv, std::nullopt},
		{"06-Nov-94 25:00:00 GMT"sv,   "DD-mth-YY HH:MM:SS GMT"sv, std::nullopt},
		{"06/Nov/94 08:49:37 GMT"sv,   "DD-mth-YY HH:MM:SS GMT"sv, std::nullopt},
		{"Funday, 06-Nov-94 08:49:37 GMT"sv, "wdy, DD-mth-YY HH:MM:SS GMT"sv, std::nullopt},
	};

	for (size_t i = 0; i < std::size(test_cases); i++) {
		DateTestCase cas_i = test_cases[i];
		std::optional<time_t> actual = tdate_parse_impl(cas_i.input);
		
		time_t original = tdate_parse((char*)cas_i.input.data());

		std::printf("[%2zu]: expected: %lld\tactual  : %lld  original: %lld\n\n", i, cas_i.expected.value_or(-1), actual.value_or(-1), original);
		
		DATE_VERIFY(actual == cas_i.expected, "not matched");

		//DATE_VERIFY(actual == original, cas_i.input.data());

	}

	//check 1 million times
	{
		auto start = std::chrono::high_resolution_clock::now();


		const int N = 1'000'000;

		for (int k = 0; k < N; k++) {
			for (size_t i = 0; i < std::size(test_cases); i++) {
				DateTestCase cas_i = test_cases[i];
				std::optional<time_t> actual = tdate_parse_impl(cas_i.input);
				//std::printf("[%2zu]: expected: %lld\nactual  : %lld\n\n", i, cas_i.expected.value_or(-1), actual.value_or(-1));
				//DATE_VERIFY(actual == cas_i.expected, "not matched");
			}
		}
		auto finish = std::chrono::high_resolution_clock::now();

		double elapsed = std::chrono::duration_cast<std::chrono::microseconds>(finish - start).count() / 1000.0;
		std::printf("elapsed : %.6f ms\n", elapsed);
		double perElement = elapsed / N / std::size(test_cases) * 1000.0;
		std::printf("per element: %.9f us \n", perElement);
	}

	//check original parser
	{
		auto start = std::chrono::high_resolution_clock::now();


		const int N = 1'000'000;

		for (int k = 0; k < N; k++) {
			for (size_t i = 0; i < std::size(test_cases); i++) {
				DateTestCase cas_i = test_cases[i];
				time_t actual = tdate_parse( (char*)cas_i.input.data() );
				//std::printf("[%2zu]: expected: %lld\nactual  : %lld\n\n", i, cas_i.expected.value_or(-1), actual.value_or(-1));
				//DATE_VERIFY(actual == cas_i.expected, "not matched");
			}
		}
		auto finish = std::chrono::high_resolution_clock::now();

		double elapsed = std::chrono::duration_cast<std::chrono::microseconds>(finish - start).count() / 1000.0;
		std::printf("elapsed : %.6f ms\n", elapsed);
		double perElement = elapsed / N / std::size(test_cases) * 1000.0;
		std::printf("per element: %.9f us \n", perElement);
	}
}

#endif 

#if 0
#include <iostream>
#include <random>
#include <array>
#include <string_view>
#include <cassert>
#include <ctime>

// Вспомогательные массивы для генерации (индексы должны совпадать с вашим БОРом)
constexpr std::string_view WDYS[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
constexpr std::string_view MTHS[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

// Быстрое zero-allocation форматирование чисел в буфер (всегда 2 символа)
constexpr void fmt_2d(char* dest, int val) {
	dest[0] = static_cast<char>('0' + (val / 10));
	dest[1] = static_cast<char>('0' + (val % 10));
}

// Форматирование дня: если < 10, то " 5", иначе "15" (для формата SPD)
constexpr void fmt_spd(char* dest, int val) {
	if (val < 10) {
		dest[0] = ' ';
		dest[1] = static_cast<char>('0' + val);
	}
	else {
		fmt_2d(dest, val);
	}
}

// Структура для хранения сгенерированной строки без аллокаций в куче
struct GeneratedFormats {
	// 8 строк. Максимальная длина формата ~30 символов + null-терминатор
	std::array<std::array<char, 32>, 8> buffers{};
};

// Функция генерации всех 8 форматов для конкретного времени
GeneratedFormats generate_all_formats(time_t t) {
	GeneratedFormats gf;

	// Используем gmtime_s (MSVC) или gmtime_r (POSIX) для потокобезопасности
#if defined(_MSC_VER)
	struct tm tm_buf;
	if (gmtime_s(&tm_buf, &t) != 0) return gf;
	const struct tm* timeptr = &tm_buf;
#else
	struct tm tm_buf;
	const struct tm* timeptr = gmtime_r(&t, &tm_buf);
	if (!timeptr) return gf;
#endif

	// Подготавливаем строковые компоненты
	std::string_view wdy = WDYS[timeptr->tm_wday];
	std::string_view mth = MTHS[timeptr->tm_mon];

	// Извлекаем компоненты времени
	int year_2d = (timeptr->tm_year + 1900) % 100;
	int day = timeptr->tm_mday;

	// Вспомогательная лямбда для сборки фиксированных частей (HH:MM:SS GMT)
	auto write_time_gmt = [&](char* p) {
		fmt_2d(p, timeptr->tm_hour); p[2] = ':';
		fmt_2d(p + 3, timeptr->tm_min); p[5] = ':';
		fmt_2d(p + 6, timeptr->tm_sec);
		p[8] = ' '; p[9] = 'G'; p[10] = 'M'; p[11] = 'T';
		};

	char* p = nullptr;

	// 0: "DD-mth-YY HH:MM:SS GMT"
	p = gf.buffers[0].data();
	fmt_2d(p, day); p[2] = '-'; mth.copy(p + 3, 3); p[6] = '-'; fmt_2d(p + 7, year_2d); p[9] = ' ';
	write_time_gmt(p + 10);

	// 1: "DD mth YY HH:MM:SS GMT"
	p = gf.buffers[1].data();
	fmt_2d(p, day); p[2] = ' '; mth.copy(p + 3, 3); p[6] = ' '; fmt_2d(p + 7, year_2d); p[9] = ' ';
	write_time_gmt(p + 10);

	// 2: "HH:MM:SS GMT DD-mth-YY"
	p = gf.buffers[2].data();
	write_time_gmt(p); p[12] = ' ';
	fmt_2d(p + 13, day); p[15] = '-'; mth.copy(p + 16, 3); p[19] = '-'; fmt_2d(p + 20, year_2d);

	// 3: "HH:MM:SS GMT DD mth YY"
	p = gf.buffers[3].data();
	write_time_gmt(p); p[12] = ' ';
	fmt_2d(p + 13, day); p[15] = ' '; mth.copy(p + 16, 3); p[19] = ' '; fmt_2d(p + 20, year_2d);

	// 4: "wdy, DD-mth-YY HH:MM:SS GMT"
	p = gf.buffers[4].data();
	wdy.copy(p, 3); p[3] = ','; p[4] = ' ';
	fmt_2d(p + 5, day); p[7] = '-'; mth.copy(p + 8, 3); p[11] = '-'; fmt_2d(p + 12, year_2d); p[14] = ' ';
	write_time_gmt(p + 15);

	// 5: "wdy, DD mth YY HH:MM:SS GMT"
	p = gf.buffers[5].data();
	wdy.copy(p, 3); p[3] = ','; p[4] = ' ';
	fmt_2d(p + 5, day); p[7] = ' '; mth.copy(p + 8, 3); p[11] = ' '; fmt_2d(p + 12, year_2d); p[14] = ' ';
	write_time_gmt(p + 15);

	// 6: "wdy mth DD HH:MM:SS GMT YY"
	p = gf.buffers[6].data();
	wdy.copy(p, 3); p[3] = ' '; mth.copy(p + 4, 3); p[7] = ' ';
	fmt_2d(p + 8, day); p[10] = ' ';
	write_time_gmt(p + 11); p[23] = ' '; fmt_2d(p + 24, year_2d);

	// 7: "wdy mth SPD HH:MM:SS GMT YY"
	p = gf.buffers[7].data();
	wdy.copy(p, 3); p[3] = ' '; mth.copy(p + 4, 3); p[7] = ' ';
	fmt_spd(p + 8, day); p[10] = ' ';
	write_time_gmt(p + 11); p[23] = ' '; fmt_2d(p + 24, year_2d);

	return gf;
}

int main() {
	// Настраиваем генератор случайных чисел для диапазона дат HTTP (например, 1970 - 2035 года)
	std::random_device rd;
	std::mt19937_64 gen(rd());

	// От 0 (01.01.1970) до 2151222400 (01.01.7135)
	std::uniform_int_distribution<time_t> dist(0, 2151222400);

	const size_t ITERATIONS = 1'000'000;
	std::cout << "Starting fuzz test for " << ITERATIONS << " random timestamps..." << std::endl;

	for (size_t i = 0; i < ITERATIONS; ++i) {
		time_t original_t = dist(gen);

		// Убираем миллисекунды, так как HTTP-форматы имеют точность до секунды
		original_t = (original_t / 1) * 1;

		GeneratedFormats gf = generate_all_formats(original_t);

		// Тестируем каждый из 8 сгенерированных вариантов строки
		for (size_t fmt_idx = 0; fmt_idx < 8; ++fmt_idx) {
			std::string_view str_to_test(gf.buffers[fmt_idx].data());

			// Вызываем ВАШ парсер
			std::optional<time_t> parsed_t = tdate_parse_impl(str_to_test);

			if (!parsed_t.has_value()) {
				std::cerr << "[FAIL] Parser returned std::nullopt!\n"
					<< "Original time_t: " << original_t << "\n"
					<< "Format index: " << fmt_idx << "\n"
					<< "String: \"" << str_to_test << "\"\n";
				return 1;
			}

			if (*parsed_t != original_t) {
				std::cerr << "[FAIL] Time mismatch!\n"
					<< "Original time_t: " << original_t << "\n"
					<< "Parsed time_t:   " << *parsed_t << "\n"
					<< "Format index: " << fmt_idx << "\n"
					<< "String: \"" << str_to_test << "\"\n";
				return 1;
			}
		}
	}

	std::cout << "[SUCCESS] All tests passed! Round-trip is 100% correct." << std::endl;
	return 0;
}
#endif

