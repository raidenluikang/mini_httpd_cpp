
#define _CRT_SECURE_NO_WARNINGS 1

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>

#include <string_view>
#include <algorithm>
#include <span>
#include <string>
#include <format>
#include <filesystem>
#include <fstream>
#include <vector>
#include <charconv>
#include <chrono>
#include <sstream>

#include "tdate_parser.hpp"

/*********************************************************************************************************************************************/
#ifdef _WIN32

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>      // ДО windows.h, покрывает sys/socket.h, netinet/in.h
#include <ws2tcpip.h>      // покрывает arpa/inet.h, netdb.h (getaddrinfo вместо gethostbyname)
#include <windows.h>       // для CreateFileMapping и т.п., если понадобится mmap-замена

#include <io.h>            // взамен части unistd.h: _read, _write, _close
#include <process.h>       // взамен части unistd.h: _getpid и т.п.

#pragma comment(lib, "Ws2_32.lib")

//FOR WINDOWS getnameinfo exists.
#define HAVE_GETNAMEINFO
#define HAVE_GETADDRINFO
#define HAVE_GAI_STRERROR
#define HAVE_SOCKADDR_IN6   // уже определяли раньше для union


#define strcasecmp _stricmp
#define strncasecmp _strnicmp

#endif //!_WIN32
/*********************************************************************************************************************************************/


#define METHOD_GET  1
#define METHOD_HEAD 2
#define METHOD_POST 3
#define METHOD_PUT  4

#define SERVER_SOFTWARE "mini_httpd_cpp/0.0 1"
#define SERVER_URL "http://www.acme.com/software/mini_httpd/"


#define ERR_DIR "errors"
#define DEFAULT_HTTP_PORT 80
#ifdef USE_SSL
#define DEFAULT_HTTPS_PORT 443
#define CERT_FILE "cert.pem"
#define KEY_FILE "key.pem"
#endif /* USE_SSL */
#define DEFAULT_USER "nobody"
#define CGI_NICE 10
#define CGI_PATH "/usr/local/bin:/usr/ucb:/bin:/usr/bin"
#define CGI_LD_LIBRARY_PATH "/usr/local/lib:/usr/lib"
#define AUTH_FILE ".htpasswd"


#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

/*********************************************************************************************************************************************/
typedef union
{
	struct sockaddr sa;
	struct sockaddr_in sa_in;
#ifdef HAVE_SOCKADDR_IN6
	struct sockaddr_in6 sa_in6;
#endif /* HAVE_SOCKADDR_IN6 */
#ifdef HAVE_SOCKADDR_STORAGE
	struct sockaddr_storage sa_stor;
#endif /* HAVE_SOCKADDR_STORAGE */
} usockaddr;


struct lookup_result_t
{
	bool gotv4P;
	bool gotv6P;
};
/*********************************************************************************************************************************************/
static lookup_result_t lookup_hostname(std::span < usockaddr> usa4P, std::span<usockaddr> usa6P);
static void handle_sigterm(int sig);
static bool match_one(std::string_view pattern, std::string_view str);
static bool match(std::string_view pattern, std::string_view  string);
static std::string b64_decode(std::string_view str);
static int hexit(char c);
static size_t strdecode(std::span<char> to, std::span<const char> from);
static socklen_t sockaddr_len(usockaddr* usaP);
static std::string ntoa(usockaddr* usaP);
static const char* get_mime_type(const char* name);
static const char* get_method_str(int m);
static void make_log_entry(void);
static void add_to_buf(std::string& bufP, const std::string_view str);
static int my_read(const std::span<char> buf);
static int my_write(const std::string_view buf);

static std::string_view get_request_line(void);

static void start_request(void);
static void add_to_request(const std::string_view str);

static void start_response(void);
static void add_to_response(const std::string_view str);
static void send_response(void);
static void add_headers(int s, const char* title, const char* extra_header, const char* mime_type, long b, time_t mod);
static void send_error_tail(void);
static bool send_error_file(const char* filename);
static void send_error_body(int s, const char* title, const char* text);
static void send_error(int s, const char* title, const char* extra_header, const char* text);
static std::string virtual_file(const char* file);
static void send_authenticate(const std::string_view realm);
static void auth_check(const std::string& dirname);

static std::vector<std::string> make_envp(void);
static std::vector<std::string> make_argp(void);
static void cgi_interpose_input(int wfd);
static void cgi_interpose_output(int rfd, int parse_headers);
static void do_cgi(void);
static void do_file(void);
static void do_dir(void);
static void de_dotdot(std::string& file);
static void handle_request(void);

static SOCKET initialize_listen_socket(usockaddr* usaP);
static void usage(void);

extern char* crypt(const char* key, const char* setting);//FIND IT.

/*********************************************************************************************************************************************/
static char* g_hostname;
static int g_port;
static char* g_argv0;

static std::string g_remoteuser;
static int g_vhost;


static long g_bytes;
static std::string g_req_hostname;
static std::string g_host;

static const char* g_path;
static const char* g_logfile;
static usockaddr g_client_addr;

static int g_method;
static const char* g_protocol;
static int g_status;

static const char* g_referer;
static std::string g_useragent;

static std::string g_query;

static const char* g_cookie;

static SOCKET g_conn_fd;


static std::string g_response;

static std::string g_request;
static int g_request_idx; // why it needed ?
static std::string g_authorization;


static long g_content_length;
static const char* g_content_type;

static std::string g_file;

static const char* g_cgi_pattern;

static time_t if_modified_since;


static int g_debug;
static const char* g_user;
static char g_hostname_buf[500];

static SOCKET g_listen4_fd, g_listen6_fd;

static int g_do_chroot;
static const char* g_pidfile;
static const char* g_charset;
static FILE* g_logfp;

 
/*********************************************************************************************************************************************/

#if 0
#include "version.h"
#include "port.h"

#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <pwd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifdef USE_SSL
#include <openssl/ssl.h>
#endif /* USE_SSL */


#define ERR_DIR "errors"
#define DEFAULT_HTTP_PORT 80
#ifdef USE_SSL
#define DEFAULT_HTTPS_PORT 443
#define CERT_FILE "cert.pem"
#define KEY_FILE "key.pem"
#endif /* USE_SSL */
#define DEFAULT_USER "nobody"
#define CGI_NICE 10
#define CGI_PATH "/usr/local/bin:/usr/ucb:/bin:/usr/bin"
#define CGI_LD_LIBRARY_PATH "/usr/local/lib:/usr/lib"
#define AUTH_FILE ".htpasswd"

#define METHOD_GET 1
#define METHOD_HEAD 2
#define METHOD_POST 3

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif


/* A multi-family sockaddr. */
typedef union {
	struct sockaddr sa;
	struct sockaddr_in sa_in;
#ifdef HAVE_SOCKADDR_IN6
	struct sockaddr_in6 sa_in6;
#endif /* HAVE_SOCKADDR_IN6 */
#ifdef HAVE_SOCKADDR_STORAGE
	struct sockaddr_storage sa_stor;
#endif /* HAVE_SOCKADDR_STORAGE */
} usockaddr;


static char* argv0;
static int debug;
static int port;
static int do_chroot;
static int vhost;
static char* user;
static char* cgi_pattern;
static char* hostname;
static char hostname_buf[500];
static u_int hostaddr;
static char* logfile;
static char* pidfile;
static char* charset;
static FILE* logfp;
static int listen4_fd, listen6_fd;
#ifdef USE_SSL
static int do_ssl;
static SSL_CTX* ssl_ctx;
#endif /* USE_SSL */


/* Request variables. */
static int conn_fd;
#ifdef USE_SSL
static SSL* ssl;
#endif /* USE_SSL */
static usockaddr client_addr;
static char* request;
static int request_size, request_len, request_idx;
static int method;
static char* path;
static char* file;
struct stat sb;
static char* query;
static char* protocol;
static int status;
static long bytes;
static char* req_hostname;

static char* authorization;
static long content_length;
static char* content_type;
static char* cookie;
static char* host;
static time_t if_modified_since;
static char* referer;
static char* useragent;

static char* remoteuser;


/* Forwards. */
static void usage(void);
static int initialize_listen_socket(usockaddr* usaP);
static void handle_request(void);
static void de_dotdot(char* file);
static void do_file(void);
static void do_dir(void);
static void do_cgi(void);
static void cgi_interpose_input(int wfd);
static void cgi_interpose_output(int rfd, int parse_headers);
static char** make_argp(void);
static char** make_envp(void);
static char* build_env(char* fmt, char* arg);
static void auth_check(char* dirname);
static void send_authenticate(char* realm);
static char* virtual_file(char* file);
static void send_error(int s, char* title, char* extra_header, char* text);
static void send_error_body(int s, char* title, char* text);
static int send_error_file(char* filename);
static void send_error_tail(void);
static void add_headers(int s, char* title, char* extra_header, char* mime_type, long b, time_t mod);
static void start_request(void);
static void add_to_request(char* str, int len);
static char* get_request_line(void);
static void start_response(void);
static void add_to_response(char* str, int len);
static void send_response(void);
static int my_read(char* buf, int size);
static int my_write(char* buf, int size);
static void add_to_buf(char** bufP, int* bufsizeP, int* buflenP, char* str, int len);
static void make_log_entry(void);
static char* get_method_str(int m);
static char* get_mime_type(char* name);
static void handle_sigterm(int sig);
static void handle_sigchld(int sig);
static void lookup_hostname(usockaddr* usa4P, size_t sa4_len, int* gotv4P, usockaddr* usa6P, size_t sa6_len, int* gotv6P);
static char* ntoa(usockaddr* usaP);
static size_t sockaddr_len(usockaddr* usaP);
static void strdecode(char* to, char* from);
static int hexit(char c);
static int b64_decode(const char* str, unsigned char* space, int size);
static int match(const char* pattern, const char* string);
static int match_one(const char* pattern, int patternlen, const char* string);

#endif 

int
main(int argc, char** argv)
{
	int argn;
	//uid_t uid;
	usockaddr host_addr4;
	usockaddr host_addr6;
	//int gotv4, gotv6;
	fd_set afdset;
	//int maxfd;
	usockaddr usa;
	int sz, r;

	/* Parse args. */
	g_argv0 = argv[0];
	g_debug = 0;
	g_port = -1;
	g_do_chroot = 0;
	g_vhost = 0;
	g_cgi_pattern = nullptr;
	g_charset = "iso-8859-1";
	g_user = DEFAULT_USER;
	g_hostname = nullptr;
	g_logfile = nullptr;
	g_pidfile = nullptr;
	g_logfp = nullptr;

#ifdef USE_SSL
	do_ssl = 0;
#endif /* USE_SSL */
	argn = 1;
	while (argn < argc && argv[argn][0] == '-')
	{
		if (strcmp(argv[argn], "-D") == 0)
			g_debug = 1;
#ifdef USE_SSL
		else if (strcmp(argv[argn], "-S") == 0)
			do_ssl = 1;
#endif /* USE_SSL */
		else if (strcmp(argv[argn], "-p") == 0 && argn + 1 < argc)
		{
			++argn;
			g_port = atoi(argv[argn]);
		}
		else if (strcmp(argv[argn], "-c") == 0 && argn + 1 < argc)
		{
			++argn;
			g_cgi_pattern = argv[argn];
		}
		else if (strcmp(argv[argn], "-u") == 0 && argn + 1 < argc)
		{
			++argn;
			g_user = argv[argn];
		}
		else if (strcmp(argv[argn], "-h") == 0 && argn + 1 < argc)
		{
			++argn;
			g_hostname = argv[argn];
		}
		else if (strcmp(argv[argn], "-r") == 0)
			g_do_chroot = 1;
		else if (strcmp(argv[argn], "-v") == 0)
			g_vhost = 1;
		else if (strcmp(argv[argn], "-l") == 0 && argn + 1 < argc)
		{
			++argn;
			g_logfile = argv[argn];
		}
		else if (strcmp(argv[argn], "-i") == 0 && argn + 1 < argc)
		{
			++argn;
			g_pidfile = argv[argn];
		}
		else if (strcmp(argv[argn], "-T") == 0 && argn + 1 < argc)
		{
			++argn;
			g_charset = argv[argn];
		}
		else
			usage();
		++argn;
	}
	if (argn != argc)
		usage();

	if (g_port == -1)
	{
#ifdef USE_SSL
		if (do_ssl)
			port = DEFAULT_HTTPS_PORT;
		else
			port = DEFAULT_HTTP_PORT;
#else /* USE_SSL */
		g_port = DEFAULT_HTTP_PORT;
#endif /* USE_SSL */
	}

	if (g_logfile != nullptr)
	{
		/* Open the log file. */
		g_logfp = fopen(g_logfile, "a");
		if (g_logfp == nullptr)
		{
			perror(g_logfile);
			exit(1);
		}
	}

	/* Look up hostname. */
	lookup_result_t lookup_result = 
	lookup_hostname( std::span<usockaddr>(& host_addr4, 1), std::span<usockaddr> (& host_addr6, 1));

	if (g_hostname == nullptr)
	{
		(void)gethostname(g_hostname_buf, sizeof(g_hostname_buf));
		g_hostname = g_hostname_buf;
	}
	if (!(lookup_result.gotv4P || lookup_result.gotv6P))
	{
		(void)fprintf(stderr, "can't find any valid address\n");
		exit(1);
	}

	/* Initialize listen sockets.  Try v6 first because of a Linux peculiarity;
	** unlike other systems, it has magical v6 sockets that also listen for v4,
	** but if you bind a v4 socket first then the v6 bind fails.
	*/
	if (lookup_result.gotv6P)
		g_listen6_fd = initialize_listen_socket(&host_addr6);
	else
		g_listen6_fd = -1;
	
	if (lookup_result.gotv4P)
		g_listen4_fd = initialize_listen_socket(&host_addr4);
	else
		g_listen4_fd = -1;

	/* If we didn't get any valid sockets, fail. */
	if (g_listen4_fd == -1 && g_listen6_fd == -1)
	{
		(void)fprintf(stderr, "can't bind to any address\n");
		exit(1);
	}

#ifdef USE_SSL
	if (do_ssl)
	{
		SSLeay_add_ssl_algorithms();
		SSL_load_error_strings();
		ssl_ctx = SSL_CTX_new(SSLv23_server_method());
		if (SSL_CTX_use_certificate_file(ssl_ctx, CERT_FILE, SSL_FILETYPE_PEM) == 0 ||
			SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_FILE, SSL_FILETYPE_PEM) == 0 ||
			SSL_CTX_check_private_key(ssl_ctx) == 0)
		{
			ERR_print_errors_fp(stderr);
			exit(1);
		}
	}
#endif /* USE_SSL */

	if (!g_debug)
	{
		/* Make ourselves a daemon. */
#ifdef HAVE_DAEMON
		if (daemon(1, 1) < 0)
		{
			perror("daemon");
			exit(1);
		}
#else
#ifndef _WIN32
		switch (fork())
		{
		case 0:
			break;
		case -1:
			perror("fork");
			exit(1);
		default:
			exit(0);
		}
#ifdef HAVE_SETSID
		(void) setsid();
#endif

#endif //!WIN32

#endif
	}
	else
	{
		/* Even if we don't daemonize, we still want to disown our parent
		** process.
		*/
#ifdef HAVE_SETSID
		(void) setsid();
#endif /* HAVE_SETSID */
	}

	if (g_pidfile != nullptr)
	{
		/* Write the PID file. */
		FILE* pidfp = fopen(g_pidfile, "w");
		if (pidfp == nullptr)
		{
			perror(g_pidfile);
			exit(1);
		}
		(void)fprintf(pidfp, "%d\n", (int)_getpid());
		(void)fclose(pidfp);
	}

	/* Read zone info now, in case we chroot(). */
	_tzset();
#ifndef _WIN32
	/* If we're root, start becoming someone else. */
	if (getuid() == 0)
	{
		struct passwd* pwd;
		pwd = getpwnam(user);
		if (pwd == (struct passwd*)0)
		{
			(void)fprintf(stderr, "%s: unknown user - '%s'\n", argv0, user);
			exit(1);
		}
		/* Set aux groups to null. */
		if (setgroups(0, (const gid_t*)0) < 0)
		{
			perror("setgroups");
			exit(1);
		}
		/* Set primary group. */
		if (setgid(pwd->pw_gid) < 0)
		{
			perror("setgid");
			exit(1);
		}
		/* Try setting aux groups correctly - not critical if this fails. */
		if (initgroups(user, pwd->pw_gid) < 0)
			perror("initgroups");
#ifdef HAVE_SETLOGIN
		/* Set login name. */
		(void) setlogin(user);
#endif /* HAVE_SETLOGIN */
		/* Save the new uid for setting after we chroot(). */
		uid = pwd->pw_uid;
	}

	/* Chroot if requested. */
	if (do_chroot)
	{
		char cwd[1000];
		(void)getcwd(cwd, sizeof(cwd) - 1);
		if (chroot(cwd) < 0)
		{
			perror("chroot");
			exit(1);
		}
		/* Always chdir to / after a chroot. */
		if (chdir("/") < 0)
		{
			perror("chroot chdir");
			exit(1);
		}

	}

	/* If we're root, become someone else. */
	if (getuid() == 0)
	{
		/* Set uid. */
		if (setuid(uid) < 0)
		{
			perror("setuid");
			exit(1);
		}
		/* Check for unnecessary security exposure. */
		if (!do_chroot)
			(void)fprintf(stderr,
				"%s: started as root without requesting chroot(), warning only\n", argv0);
	}

	/* Catch various termination signals. */
	(void)signal(SIGTERM, handle_sigterm);
	(void)signal(SIGINT, handle_sigterm);

	(void)signal(SIGHUP, handle_sigterm);
	(void)signal(SIGUSR1, handle_sigterm);

	/* Catch defunct children. */
	(void)signal(SIGCHLD, handle_sigchld);

	/* And get EPIPE instead of SIGPIPE. */
	(void)signal(SIGPIPE, SIG_IGN);
#endif //!_WIN32

	/* Main loop. */
	for (;;)
	{
		/* Possibly do a select() on the possible two listen fds. */
		FD_ZERO(&afdset);
		SOCKET maxfd = -1;
		if (g_listen4_fd != -1)
		{
			FD_SET(g_listen4_fd, &afdset);
			if (g_listen4_fd > maxfd)
				maxfd = g_listen4_fd;
		}
		if (g_listen6_fd != -1)
		{
			FD_SET(g_listen6_fd, &afdset);
			if (g_listen6_fd > maxfd)
				maxfd = g_listen6_fd;
		}
		if (g_listen4_fd != -1 && g_listen6_fd != -1)
			if (select( (int)maxfd + 1, &afdset, (fd_set*)0, (fd_set*)0, (struct timeval*)0) < 0)
			{
				perror("select");
				exit(1);
			}
		/* (If we don't have two listen fds, we can just skip the select()
		** and fall through.  Whichever listen fd we do have will do a
		** blocking accept() instead.)
		*/

		/* Accept the new connection. */
		sz = sizeof(usa);
		if (g_listen4_fd != -1 && FD_ISSET(g_listen4_fd, &afdset))
			g_conn_fd = accept(g_listen4_fd, &usa.sa, &sz);
		else if (g_listen6_fd != -1 && FD_ISSET(g_listen6_fd, &afdset))
			g_conn_fd = accept(g_listen6_fd, &usa.sa, &sz);
		else
		{
			(void)fprintf(stderr, "%s: select failure\n", g_argv0);
			exit(1);
		}
		if (g_conn_fd < 0)
		{
			if (errno == EINTR)
				continue;	/* try again */
			perror("accept");
			exit(1);
		}

		/* Fork a sub-process to handle the connection. */
		//r = fork();
		r = 0;
		if (r < 0)
		{
			perror("fork");
			exit(1);
		}
		if (r == 0)
		{
			/* Child process. */
			g_client_addr = usa;
			
			if (g_listen4_fd != -1)
				(void)closesocket(g_listen4_fd);
			
			if (g_listen6_fd != -1)
				(void)closesocket(g_listen6_fd);

			handle_request();
			exit(0);
		}
		(void)closesocket(g_conn_fd);
	}
}




static void usage(void)
{
#ifdef USE_SSL
	(void) fprintf(stderr, "usage:  %s [-D] [-S] [-p port] [-c cgipat] [-u user] [-h hostname] [-r] [-v] [-l logfile] [-i pidfile] [-T charset]\n", g_argv0);
#else /* USE_SSL */
	(void)fprintf(stderr, "usage:  %s [-D] [-p port] [-c cgipat] [-u user] [-h hostname] [-r] [-v] [-l logfile] [-i pidfile] [-T charset]\n", g_argv0);
#endif /* USE_SSL */
	exit(1);
}

static SOCKET
initialize_listen_socket(usockaddr* usaP)
{
	SOCKET listen_fd;
	int i;

	listen_fd = socket(usaP->sa.sa_family, SOCK_STREAM, 0);
	if (listen_fd < 0)
	{
		perror("socket");
		return -1;
	}
#ifndef _WIN32
	(void)fcntl(listen_fd, F_SETFD, 1);
#endif 
	i = 1;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&i, sizeof(i)) < 0)
	{
		perror("setsockopt");
		return -1;
	}
	if (bind(listen_fd, &usaP->sa, sockaddr_len(usaP)) < 0)
	{
		perror("bind");
		return -1;
	}
	if (listen(listen_fd, 1024) < 0)
	{
		perror("listen");
		return -1;
	}
	return listen_fd;
}



/* This runs in a child process, and exits when done, so cleanup is
** not needed.
*/
static void handle_request(void)
{
	//const char* method_str;
	//char* line;
	//char* cp;

	/* Initialize the request variables. */
	g_remoteuser = "";
	g_method = -1;
	g_path = nullptr;
	g_file = "";
	g_query = "";
	g_protocol = "HTTP/1.0";
	g_status = 0;
	g_bytes = -1;
	g_req_hostname = "";

	g_authorization = "";
	g_content_type = nullptr;
	g_content_length = -1;
	g_cookie = nullptr;
	g_host = "";
	if_modified_since = (time_t)-1;
	g_referer = "";
	g_useragent = "";

#ifdef USE_SSL
	if (do_ssl)
	{
		ssl = SSL_new(ssl_ctx);
		SSL_set_fd(ssl, conn_fd);
		if (SSL_accept(ssl) == 0)
		{
			ERR_print_errors_fp(stderr);
			exit(1);
		}
	}
#endif /* USE_SSL */

	/* Read in the request. */
	start_request();
	
	char buf[10000];
	
	for (;;)
	{
		std::span<char> buf_c(buf, sizeof(buf));

		int r = my_read(buf_c);
		if (r <= 0)
			break;
		
		add_to_request(std::string_view{buf, (size_t)r});


		//if (strstr(g_request, "\r\n\r\n") != (char*)0 ||
		//	strstr(g_request, "\n\n") != (char*)0)
		//	break;
		if (g_request.find("\r\n\r\n") != g_request.npos ||
			g_request.find("\n\n") != g_request.npos)
		{
			break;
		}
	}


	/* Parse the first line of the request. */
	std::string_view method_str = get_request_line();
	//g_path = strpbrk(method_str, " \t\n\r");

	//if (g_path == nullptr)
	//{
	//	send_error(400, "Bad Request", nullptr, "Can't parse request.");
	//}

	//*g_path++ = '\0';
	size_t pos = method_str.find_first_of(" \t\n\r");
	if (pos == method_str.npos) {
		send_error(400, "Bad Request", nullptr, "Can't parse request.");
	}
	
	

	g_path += strspn(g_path, " \t\n\r");
	g_protocol = strpbrk(g_path, " \t\n\r");
	if (g_protocol == nullptr)
	{
		send_error(400, "Bad Request", nullptr, "Can't parse request.");
	}
	//*g_protocol++ = '\0';
	
	{
		const char* query = strchr(g_path, '?');
		if (query == nullptr)
			g_query = "";
		else
			//*query++ = '\0';
			g_query = query + 1;
	}

	/* Parse the rest of the request headers. */
	std::string_view line;
	
	while ((line = get_request_line()).size() > 0 )
	{
		const char* cp;

		if (line[0] == '\0')
			break;
		else if (strncasecmp(line.data(), "Authorization:", 14) == 0)
		{
			cp = &line[14];
			cp += strspn(cp, " \t");
			g_authorization = cp;
		}
		else if (strncasecmp(line.data(), "Content-Length:", 15) == 0)
		{
			cp = &line[15];
			cp += strspn(cp, " \t");
			g_content_length = atol(cp);
		}
		else if (strncasecmp(line.data(), "Content-Type:", 13) == 0)
		{
			cp = &line[13];
			cp += strspn(cp, " \t");
			g_content_type = cp;
		}
		else if (strncasecmp(line.data(), "Cookie:", 7) == 0)
		{
			cp = &line[7];
			cp += strspn(cp, " \t");
			g_cookie = cp;
		}
		else if (strncasecmp(line.data(), "Host:", 5) == 0)
		{
			cp = &line[5];
			cp += strspn(cp, " \t");
			g_host = cp;
		}
		else if (strncasecmp(line.data(), "If-Modified-Since:", 18) == 0)
		{
			cp = &line[18];
			cp += strspn(cp, " \t");
			if_modified_since = mini_httpd::tdate_parse(cp).value_or(-1);
		}
		else if (strncasecmp(line.data(), "Referer:", 8) == 0)
		{
			cp = &line[8];
			cp += strspn(cp, " \t");
			g_referer = cp;
		}
		else if (strncasecmp(line.data(), "User-Agent:", 11) == 0)
		{
			cp = &line[11];
			cp += strspn(cp, " \t");
			g_useragent = cp;
		}
	}

	if (strcasecmp(method_str.data(), get_method_str(METHOD_GET)) == 0)
		g_method = METHOD_GET;
	else if (strcasecmp(method_str.data(), get_method_str(METHOD_HEAD)) == 0)
		g_method = METHOD_HEAD;
	else if (strcasecmp(method_str.data(), get_method_str(METHOD_POST)) == 0)
		g_method = METHOD_POST;
	else if (strcasecmp(method_str.data(), get_method_str(METHOD_PUT)) == 0)
		g_method = METHOD_PUT;
	else
		send_error(501, "Not Implemented", nullptr, "That method is not implemented.");


	//strdecode(g_path, g_path);
	if (g_path[0] != '/')
	{
		send_error(400, "Bad Request", nullptr, "Bad filename.");
	}

	g_file = g_path + 1;  //&(path[1]);
	
	if (g_file[0] == '\0')
		g_file = "./";

	de_dotdot(g_file);
	
	if (g_file[0] == '/' ||
		(g_file[0] == '.' && g_file[1] == '.' &&
		(g_file[2] == '\0' || g_file[2] == '/'))) 
	{
		send_error(400, "Bad Request", (char*)0, "Illegal filename.");
	}

	if (g_vhost)
	{
		g_file = virtual_file(g_file.c_str());
	}

	std::error_code ec{};
	std::filesystem::path fpath(g_file);
	if (!std::filesystem::exists(fpath, ec)) {
		send_error(404, "Not Found", nullptr, "File not found.");
	}
	if (ec) {
		send_error(404, "Not Found", nullptr, "File not found.");
	}

	if (!std::filesystem::is_directory(fpath, ec)) {
		do_file();
	}
	//if (stat(file.c_str(), &sb) < 0)
	//	send_error(404, "Not Found", (char*)0, "File not found.");
	//if (!S_ISDIR(sb.st_mode))
	//	do_file();
	else
	{
		//char idx[10000];
		//if (file[strlen(file) - 1] != '/')
		if (!g_file.ends_with('/'))
		{
			//char location[10000];
			//(void)snprintf(location, sizeof(location), "Location: %s/", path);
			std::string location = std::format("Location: {}/", g_path);
			send_error(302, "Found", location.c_str(), "Directories must end with a slash.");
		}
		
		//(void)snprintf(idx, sizeof(idx), "%sindex.html", file);
		
		std::string idx = std::format("{}index.html", g_file);

		//if (stat(idx, &sb) >= 0)
		if (std::filesystem::exists(std::filesystem::path(idx), ec))
		{
			g_file = idx;
			do_file();
		}
		else
		{
			//(void)snprintf(idx, sizeof(idx), "%sindex.htm", file);
			idx = std::format("{}index.htm", g_file);

			//if (stat(idx, &sb) >= 0)
			if (std::filesystem::exists(std::filesystem::path(idx), ec))
			{
				g_file = idx;
				do_file();
			}
			else
			{
				//(void)snprintf(idx, sizeof(idx), "%sindex.cgi", file);
				
				idx = std::format("{}index.cgi", g_file);

				//if (stat(idx, &sb) >= 0)
				if (std::filesystem::exists(std::filesystem::path(idx), ec))
				{
					g_file = idx;
					do_file();
				}
				else
				{
					do_dir();
				}
			}
		}
	}

#ifdef USE_SSL
	SSL_free(ssl);
#endif /* USE_SSL */
}


static void de_dotdot(std::string& file)
{
	using namespace std::literals::string_view_literals;

	size_t dot_dot_pos = file.find("/../"sv);
	
	while (dot_dot_pos != file.npos) 
	{
		if (dot_dot_pos == 0) 
		{
			//start position, do not allowed.
			
			// remove first 4 symbols

			file.erase(0, 4);
		}
		else 
		{
			size_t prev_sl = file.rfind('/', dot_dot_pos - 1);
			if (prev_sl == file.npos) {
				// there no '/' before '/../' so remove whole all
				//  file:  x/../t  => t

				file.erase(0, dot_dot_pos + 4);
			}
			else {
				// file:   x/y/z/../t/h  ==> x/y/t/h
				//remove z/../
				file.erase(prev_sl + 1, dot_dot_pos + 3 - prev_sl);
			}
		}
		dot_dot_pos = file.find("/../"sv);
	}

	/* Also elide any xxx/.. at the end. */
	while (file.ends_with("/.."sv)) {
		dot_dot_pos = file.length() - 3;
		if (dot_dot_pos == 0) {
			file.erase(0, 3);
		}
		else {
			size_t prev_sl = file.rfind('/', dot_dot_pos - 1);
			if (prev_sl == file.npos) {
				// there no '/' before '/../' so remove whole all
				//  file:  x/../t  => t

				file.erase(0, dot_dot_pos + 3);
			}
			else {
				// file:   x/y/z/../t/h  ==> x/y/t/h
				//remove z/../
				file.erase(prev_sl + 1, dot_dot_pos + 2 - prev_sl);
			}
		}
	}

	//char* cp;
	//char* cp2;
	//int l;

	///* Elide any xxx/../ sequences. */
	//while ((cp = strstr(file, "/../")) != nullptr)
	//{
	//	for (cp2 = cp - 1; cp2 >= file && *cp2 != '/'; --cp2)
	//		continue;

	//	if (cp2 < file)
	//		break;

	//	(void)strcpy(cp2, cp + 3);
	//}

	///* Also elide any xxx/.. at the end. */
	//while ((l = strlen(file)) > 3 &&
	//	strcmp((cp = file + l - 3), "/..") == 0)
	//{
	//	for (cp2 = cp - 1; cp2 >= file && *cp2 != '/'; --cp2)
	//		continue;
	//	if (cp2 < file)
	//		break;
	//	*cp2 = '\0';
	//}
}


// Функция-помощник для конвертации времени Windows в UNIX time_t
static time_t filetime_to_timet(const FILETIME* ft) {
	ULARGE_INTEGER ull;
	ull.LowPart = ft->dwLowDateTime;
	ull.HighPart = ft->dwHighDateTime;
	// Windows считает 100-наносекундные интервалы с 1 января 1601 года.
	// Вычитаем разницу до 1 января 1970 года (11644473600 секунд).
	return (time_t)((ull.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

// Пример функции для отправки файла в сокет через отображение памяти на Windows
static void send_file_windows(const char* filepath, SOCKET socket_fd) {
	// 1. Открываем файл через Win32 API
	HANDLE hFile = CreateFileA(
		filepath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Ошибка открытия файла: %d\n", GetLastError());
		send_error(403, "Forbidden", nullptr, "File is protected.");
		return;
	}


	FILETIME ftLastWrite;
	time_t file_mtime = 0;
	LARGE_INTEGER fileSize;

	// 2. Получаем размер файла
	if (!GetFileSizeEx(hFile, &fileSize)) {
		CloseHandle(hFile);
		send_error(403, "Forbidden", nullptr, "File is protected.");
		return;
	}

	// Если файл пустой, проецировать нельзя
	if (fileSize.QuadPart == 0) 
	{
		CloseHandle(hFile);
		send_error(403, "Forbidden", nullptr, "File is empty.");
		return;
	}

	// Проверяем, помещается ли файл в стандартный int
	if (fileSize.QuadPart > INT_MAX) {
		// Отправляем HTTP-ошибку "Внутренняя ошибка сервера" или "Файл слишком большой"
		add_headers(
			500, "Internal Server Error", nullptr, "text/html", 0, (time_t)(-1) 
		);
		
		send_response();

		// Также можно отправить простое HTML-сообщение об ошибке в сокет
		const char* error_msg = "<h1>500 Internal Server Error</h1><p>File is too large to process.</p>";
		send(socket_fd, error_msg, (int)strlen(error_msg), 0);

		CloseHandle(hFile);
		return;
	}

	if (GetFileTime(hFile, NULL, NULL, &ftLastWrite)) {
		file_mtime = filetime_to_timet(&ftLastWrite);
	}


	const char* type = get_mime_type(g_file.c_str());
	char fixed_type[500];
	(void)snprintf(fixed_type, sizeof(fixed_type), type, g_charset);

	// 3. Та самая логика проверки из mini_httpd
	if (if_modified_since != (time_t)-1 && if_modified_since >= file_mtime)
	{
		// Вместо sb.st_size передаем fileSize.QuadPart, вместо sb.st_mtime — file_mtime
		add_headers(304, "Not Modified", nullptr, fixed_type,
			(long)fileSize.QuadPart, file_mtime
		);

		send_response();

		// Не забываем закрыть хэндл файла перед выходом!
		CloseHandle(hFile);
		return;
	}

	// 3. Создаем объект проекции файла (аналог подготовки к mmap)
	HANDLE hMapping = CreateFileMappingA(
		hFile,
		NULL,
		PAGE_READONLY,
		0, 0, // 0, 0 означает проецировать файл целиком
		NULL
	);

	if (hMapping == NULL) {
		printf("Ошибка CreateFileMapping: %d\n", GetLastError());
		CloseHandle(hFile);
		return;
	}

	// 4. Отображаем файл в память процесса (собственно, сам mmap)
	const char* pFileData = (const char*)MapViewOfFile(
		hMapping,
		FILE_MAP_READ,
		0, 0, // Смещение 0
		0     // Размер 0 (весь файл)
	);

	if (pFileData == NULL) {
		printf("Ошибка MapViewOfFile: %d\n", GetLastError());
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return;
	}

	// 5. Теперь pFileData — это указатель на данные файла в памяти.
	// Передаем данные в сетевой сокет Windows (Winsock)
	// В Windows вместо write() для сокетов используется send()
	
	int bytes_sent = send(socket_fd, pFileData, (int)fileSize.QuadPart, 0);
	if (bytes_sent == SOCKET_ERROR) {
		printf("Ошибка отправки в сокет: %d\n", WSAGetLastError());
	}

	// 6. Очистка ресурсов (в обратном порядке)
	UnmapViewOfFile(pFileData);
	CloseHandle(hMapping);
	CloseHandle(hFile);
}

static void do_file(void)
{
	//char buf[10000];
	//char* type;
	//char fixed_type[500];
	//char* cp;
	//int fd;
	//void* ptr;

	/* Check authorization for this directory. */
	{
		//(void)strncpy(buf, file, sizeof(buf));

		//cp = strrchr(buf, '/');

		//if (cp == (char*)0)
		//	(void)strcpy(buf, ".");
		//else
		//	*cp = '\0';
		
		//1. file copied to buf
		//2. find last '/' symbol.
		//  2.1  if there no '/'symbol ,  buf became current directory "."
		//  2.2  if there exists '/', so remove tail from buf
		std::string buf = g_file;
		const size_t pos = buf.find('/');
		if (pos == buf.npos) 
		{
			buf = ".";
		}
		else 
		{
			buf.erase(pos, buf.size());
		}

		auth_check(buf);
	}

	/* Check if the filename is the AUTH_FILE itself - that's verboten. */
	{
		//if (strcmp(file, AUTH_FILE) == 0 ||
		//	(strcmp(&(file[strlen(file) - sizeof(AUTH_FILE) + 1]), AUTH_FILE) == 0 &&
		//		file[strlen(file) - sizeof(AUTH_FILE)] == '/'))
		//	send_error(403, "Forbidden", (char*)0, "File is protected.");

		if (g_file == AUTH_FILE ||
			(g_file.ends_with(AUTH_FILE) && g_file[g_file.size() - sizeof(AUTH_FILE)] == '/')
			) {
			send_error(403, "Forbidden", nullptr, "File is protected.");
		}
	}

	/* Is it CGI? */
	if (g_cgi_pattern != nullptr && match(g_cgi_pattern, g_file))
	{
		do_cgi();
		return;
	}
#ifndef _WIN32
	fd = open(file, O_RDONLY);
	if (fd < 0)
		send_error(403, "Forbidden", (char*)0, "File is protected.");
	type = get_mime_type(file);
	(void)snprintf(fixed_type, sizeof(fixed_type), type, charset);
	if (if_modified_since != (time_t)-1 &&
		if_modified_since >= sb.st_mtime)
	{
		add_headers(
			304, "Not Modified", (char*)0, fixed_type, sb.st_size,
			sb.st_mtime);
		send_response();
		return;
	}
	add_headers(200, "Ok", (char*)0, fixed_type, sb.st_size, sb.st_mtime);
	send_response();
	if (method == METHOD_HEAD)
		return;
	if (sb.st_size > 0)	/* avoid zero-length mmap */
	{
		ptr = mmap(0, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
		if (ptr != (void*)-1)
		{
			(void)my_write(ptr, sb.st_size);
			(void)munmap(ptr, sb.st_size);
		}
	}
	(void)close(fd);
#else 
	
	send_file_windows(g_file.c_str(), g_conn_fd);
#endif
}





static std::string generate_directory_listing(const std::string& dirPath)
{
	namespace fs = std::filesystem;

	std::ostringstream html;

	std::error_code ec;
	for (const auto& entry : fs::directory_iterator(dirPath, ec))
	{
		if (ec)
			break;

		const std::string name = entry.path().filename().string();

		// пропускаем "." — аналог того, что делал ls в этом контексте
		if (name == ".")
			continue;

		std::error_code sizeEc;
		const bool isDir = entry.is_directory(sizeEc);
		const auto fileSize = isDir ? 0 : entry.file_size(sizeEc);

		// HTML-экранирование имени — обязательно, иначе имя файла типа
		// "<script>...</script>" стало бы XSS-уязвимостью в листинге
		auto htmlEscape = [](const std::string& s)
			{
				std::string out;
				for (char c : s)
				{
					switch (c)
					{
					case '<': out += "&lt;"; break;
					case '>': out += "&gt;"; break;
					case '&': out += "&amp;"; break;
					case '"': out += "&quot;"; break;
					default:  out += c;
					}
				}
				return out;
			};

		const std::string escaped = htmlEscape(name);
		const std::string displayName = isDir ? escaped + "/" : escaped;

		html << "<A HREF=\"" << escaped << (isDir ? "/" : "") << "\">"
			<< displayName << "</A>";

		if (!isDir)
			html << "  " << fileSize << " bytes";

		html << "<br>\n";
	}

	return html.str();
}

static void do_dir(void)
{
	//char buf[10000];
	//int buflen;
	//char command[10000];
	//char* contents;
	//int contents_size, contents_len;
	//FILE* fp;
	
	std::string contents;

	/* Check authorization for this directory. */
	auth_check(g_file);

	//contents_size = 0;
	//buflen = snprintf(buf, sizeof(buf),
	//	"<HTML><HEAD><TITLE>Index of %s</TITLE></HEAD>\n<BODY BGCOLOR=\"#99cc99\"><H4>Index of %s</H4>\n<PRE>\n",
	//	file, file);
	contents = std::format("<HTML><HEAD><TITLE>Index of {}</TITLE></HEAD>\n<BODY BGCOLOR=\"#99cc99\"><H4>Index of {}</H4>\n<PRE>\n", g_file, g_file);
	//add_to_buf(&contents, &contents_size, &contents_len, buf, buflen);

	/* Magic HTML ls command! */
	//if (strchr(file, '\'') == (char*)0)
	//{
	//	(void)snprintf(
	//		command, sizeof(command),
	//		"ls -lgF '%s' | tail +2 | sed -e 's/^\\([^ ][^ ]*\\)\\(  *[^ ][^ ]*  *[^ ][^ ]*  *[^ ][^ ]*\\)\\(  *[^ ][^ ]*\\)  *\\([^ ][^ ]*  *[^ ][^ ]*  *[^ ][^ ]*\\)  *\\(.*\\)$/\\1 \\3  \\4  |\\5/' -e '/ -> /!s,|\\([^*]*\\)$,|<A HREF=\"\\1\">\\1</A>,' -e '/ -> /!s,|\\(.*\\)\\([*]\\)$,|<A HREF=\"\\1\">\\1</A>\\2,' -e '/ -> /s,|\\([^@]*\\)\\(@* -> \\),|<A HREF=\"\\1\">\\1</A>\\2,' -e 's/|//'",
	//		file);
	//	fp = popen(command, "r");
	//	for (;;)
	//	{
	//		int r;
	//		r = fread(buf, 1, sizeof(buf), fp);
	//		if (r <= 0)
	//			break;
	//		add_to_buf(&contents, &contents_size, &contents_len, buf, r);
	//	}
	//	(void)pclose(fp);
	//}

	contents += generate_directory_listing(g_file);

	/*buflen = snprintf(buf, sizeof(buf),
		"</PRE>\n<HR>\n<ADDRESS><A HREF=\"%s\">%s</A></ADDRESS>\n</BODY></HTML>\n",
		SERVER_URL, SERVER_SOFTWARE);
	add_to_buf(&contents, &contents_size, &contents_len, buf, buflen);*/
	
	contents += std::format("</PRE>\n<HR>\n<ADDRESS><A HREF=\"{}\">{}</A></ADDRESS>\n</BODY></HTML>\n", SERVER_URL, SERVER_SOFTWARE);

	add_headers(200, "Ok", nullptr, "text/html", (long)contents.length(), time_t(-1) );
	
	if (g_method == METHOD_HEAD)
	{
		send_response();
		return;
	}
	add_to_response(contents);
	send_response();
}


static void do_cgi(void)
{
	//char** argp;
	//char** envp;
	int parse_headers;
	const char* binary;
	char* directory;

	if (g_method != METHOD_GET && g_method != METHOD_POST) 
	{
		send_error(501, "Not Implemented", nullptr, "That method is not implemented for CGI.");
	}

	/* Make the environment vector. */
	std::vector<std::string> envp = make_envp();

	/* Make the argument vector. */
	std::vector<std::string> argp = make_argp();

	/* Set up stdin.  For POSTs we may have to set up a pipe from an
	** interposer process, depending on if we've read some of the data
	** into our buffer.  We also have to do this for all SSL CGIs.
	*/
#ifdef USE_SSL
	if ((method == METHOD_POST && request_len > request_idx) || do_ssl)
#else /* USE_SSL */
	if ((g_method == METHOD_POST && g_request.length() > g_request_idx))
#endif /* USE_SSL */
	{
		int p[2];
		int r;

		if (_pipe(p, 0, 0) < 0)
		{
			send_error(500, "Internal Error", (char*)0, "Something unexpected went wrong making a pipe.");
		}

		//r = fork();
		r = 0;
		if (r < 0)
		{
			send_error(500, "Internal Error", (char*)0, "Something unexpected went wrong forking an interposer.");
		}
		
		if (r == 0)
		{
			/* Interposer process. */
			(void)_close(p[ 0 ]);
			cgi_interpose_input( p[ 1 ] );
			exit(0);
		}
		(void)_close(p[ 1 ]);
		
#ifndef _WIN32
		(void)dup2(g_conn_fd, STDIN_FILENO);
#else
		// TODO: CGI на Windows требует другого механизма (WSADuplicateSocket / pipes),
		// не прямого аналога dup2 для SOCKET. Пока не реализовано — см. обсуждение.
#pragma message("CGI support not yet implemented on Windows")
#endif

		//(void)dup2(p[0], STDIN_FILENO);
	}
	else
	{
		/* Otherwise, the request socket is stdin. */
		//(void)dup2(g_conn_fd, STDIN_FILENO);
#ifndef _WIN32
		(void)dup2(g_conn_fd, STDIN_FILENO);
#else
	// TODO: CGI на Windows требует другого механизма (WSADuplicateSocket / pipes),
	// не прямого аналога dup2 для SOCKET. Пока не реализовано — см. обсуждение.
#pragma message("CGI support not yet implemented on Windows")
#endif
	}

	/* Set up stdout/stderr.  For SSL, or if we're doing CGI header parsing,
	** we need an output interposer too.
	*/
	//if (/*strncmp(argp[0], "nph-", 4) == 0*/)
	using namespace std::literals::string_view_literals;
	if (argp[0].starts_with("nph-"sv))
		parse_headers = 0;
	else
		parse_headers = 1;

#ifdef USE_SSL
	if (parse_headers || do_ssl)
#else /* USE_SSL */
	if (parse_headers)
#endif /* USE_SSL */
	{
		int p[2];
		int r;

		if (_pipe(p, 0, 0) < 0)
			send_error(500, "Internal Error", (char*)0, "Something unexpected went wrong making a pipe.");

		//r = fork();
		r = 0;
		if (r < 0)
			send_error(500, "Internal Error", (char*)0, "Something unexpected went wrong forking an interposer.");
		if (r == 0)
		{
			/* Interposer process. */
			(void)_close(p[1]);
			cgi_interpose_output(p[0], parse_headers);
			exit(0);
		}
		(void)_close(p[0]);

		(void)_dup2(p[1], STDOUT_FILENO);
		(void)_dup2(p[1], STDERR_FILENO);

	}
	else
	{
#ifndef _WIN32
		/* Otherwise, the request socket is stdout/stderr. */
		(void)dup2(g_conn_fd, STDOUT_FILENO);
		(void)dup2(g_conn_fd, STDERR_FILENO);
#else 
#pragma message("CGI support not yet implemented on Windows")
#endif 
	}

	/* Set priority. */
	//(void)nice(CGI_NICE);

	/* Split the program into directory and binary, so we can chdir()
	** to the program's own directory.  This isn't in the CGI 1.1
	** spec, but it's what other HTTP servers do.
	*/
	directory = _strdup(g_file.c_str());
	if (directory == (char*)0)
		binary = g_file.c_str();	/* ignore errors */
	else
	{
		char* binary_l = strrchr(directory, '/');
		if (binary_l == (char*)0)
			binary = g_file.c_str();
		else
		{
			*binary_l++ = '\0';
			
			binary = binary_l;
#ifndef _WIN32
			(void)chdir(directory);	/* ignore errors */
#else 
			SetCurrentDirectoryA(directory);
#endif
		}
	}

	/* Default behavior for SIGPIPE. */
	//(void)signal(SIGPIPE, SIG_DFL);

	/* Run the program. */
	//(void)execve(binary, argp, envp);

	/* Something went wrong. */
	send_error(500, "Internal Error", (char*)0, "Something unexpected went wrong running a CGI program.");
}


/* This routine is used only for POST requests.  It reads the data
** from the request and sends it to the child process.  The only reason
** we need to do it this way instead of just letting the child read
** directly is that we have already read part of the data into our
** buffer.
**
** Oh, and it's also used for all SSL CGIs.
*/
static void
cgi_interpose_input(int wfd)
{
	int r;
	char buf[1024];

	int c = (int)g_request.length()  - g_request_idx;
	if (c > 0)
	{
		if (_write(wfd, &(g_request[g_request_idx]), c) != c)
			return;
	}
	
	if (c < 0)
		c = 0;

	while (c < g_content_length)
	{
		size_t bsz = std::min<size_t>(sizeof(buf), g_content_length - c);
		r = my_read( std::span(buf,bsz) );
		
		if (r == 0)
		{
			//sleep(1);
			Sleep(1000);
		}
		else if (r < 0)
		{
			if (errno == EAGAIN)
				//sleep(1);
				Sleep(1000);
			else
				return;
		}
		else
		{
			if (_write(wfd, buf, r) != r)
				return;
			c += r;
		}
	}
}


/* This routine is used for parsed-header CGIs and for all SSL CGIs. */
static void cgi_interpose_output(int rfd, int parse_headers)
{
	//int r;
	char buf[1024];

	if (!parse_headers)
	{
		/* If we're not parsing headers, write out the default status line
		** and proceed to the echo phase.
		*/
		(void)my_write("HTTP/1.0 200 OK\r\n");
	}
	else
	{
		/* Header parsing.  The idea here is that the CGI can return special
		** headers such as "Status:" and "Location:" which change the return
		** status of the response.  Since the return status has to be the very
		** first line written out, we have to accumulate all the headers
		** and check for the special ones before writing the status.  Then
		** we write out the saved headers and proceed to echo the rest of
		** the response.
		*/
		//int headers_size, headers_len;
		//char* headers;
		//char* br;
		int status;
		const char* title;
		//char* cp;

		std::string headers;
		/* Slurp in all headers. */
		//headers_size = 0;
		//add_to_buf(&headers, &headers_size, &headers_len, (char*)0, 0);
		size_t br = 0;
		for (;;)
		{
			size_t r = _read(rfd, buf, sizeof(buf));
			if (r == 0)
			{
				//br = &(headers[headers_len]);
				br = headers.size();
				break;
			}
			
			add_to_buf(headers, std::string_view{ buf, r });

			br = headers.find("\r\n\r\n");
			if (br != headers.npos)
				break;
			br = headers.find("\n\n");
			if (br != headers.npos)
				break;
			//if ((br = strstr(headers, "\r\n\r\n")) != (char*)0 ||
			//	(br = strstr(headers, "\n\n")) != (char*)0)
			//	break;
		}

		/* Figure out the status. */
		status = 200;
		//if ((cp = strstr(headers, "Status:")) != (char*)0 &&
		//	cp < br &&
		//	(cp == headers || *(cp - 1) == '\n'))
		
		size_t cp = headers.find("Status:");
		if (cp != headers.npos && 
			cp < br && 
			(cp == 0 || headers[cp-1] == '\n'))
		{

			cp += 7;// S T A T U S:
			while (cp < headers.size() && (headers[cp] == ' ' || headers[cp] == '\t'))
				++cp;
			// headers[cp ..end)
			// 
			//cp += strspn(cp, " \t");
			//status = atoi(cp);
			auto [ptr, ec] = std::from_chars(headers.data() + cp, headers.data() + headers.size(), status);
		
			if (ec != std::errc{}) 
			{
				//can't parse status , 
				fprintf(stderr, "http response has status header but value not parsable.");
				exit(1);
			}
		}

		cp = headers.find("Location:");
		
		if (cp != headers.npos && cp < br && (cp == 0 || headers[cp - 1] == '\n'))
		{
			status = 302;
		}

		//if ((cp = strstr(headers, "Location:")) != (char*)0 &&
		//	cp < br &&
		//	(cp == headers || *(cp - 1) == '\n'))
		//	status = 302;

		/* Write the status line. */
		switch (status)
		{
		case 200: title = "OK"; break;
		case 302: title = "Found"; break;
		case 304: title = "Not Modified"; break;
		case 400: title = "Bad Request"; break;
		case 401: title = "Unauthorized"; break;
		case 403: title = "Forbidden"; break;
		case 404: title = "Not Found"; break;
		case 408: title = "Request Timeout"; break;
		case 500: title = "Internal Error"; break;
		case 501: title = "Not Implemented"; break;
		case 503: title = "Service Temporarily Overloaded"; break;
		default: title = "Something"; break;
		}

		//(void)snprintf(
		//	buf, sizeof(buf), "HTTP/1.0 %d %s\r\n", status, title);

		(void)my_write(std::format("HTTP/1.0 {} {}\r\n", status, title));

		/* Write the saved headers. */
		(void)my_write(headers);
	}

	/* Echo the rest of the output. */
	for (;;)
	{
		size_t r = _read(rfd, buf, sizeof(buf));
		
		if (r == 0)
			return;
		
		if (my_write(std::string_view{ buf, r }) != r)
			return;
	}
}



/* Set up CGI argument vector.  We don't have to worry about freeing
** stuff since we're a sub-process.  This gets done after make_envp() because
** we scribble on query.
*/
static std::vector<std::string> make_argp(void)
{
	//char** argp;
	//int argn;
	//char* cp1;
	//char* cp2;

	/* By allocating an arg slot for every character in the query, plus
	** one for the filename and one for the NULL, we are guaranteed to
	** have enough.  We could actually use strlen/2.
	*/
	//argp = (char**)malloc((strlen(g_query) + 2) * sizeof(char*));
	std::vector<std::string> argp;
	
	//argp[0] = strrchr(file, '/');
	//if (argp[0] != (char*)0)
	//	++argp[0];
	//else
	//	argp[0] = file;

	size_t pos = g_file.rfind('/'); // find last '/'
	if (pos != g_file.npos)
		argp.push_back( g_file.substr(pos + 1) );
	else
		argp.push_back( g_file ) ;


	//argn = 1;
	/* According to the CGI spec at http://hoohoo.ncsa.uiuc.edu/cgi/cl.html,
	** "The server should search the query information for a non-encoded =
	** character to determine if the command line is to be used, if it finds
	** one, the command line is not to be used."
	*/
	//if (strchr(query, '=') == (char*)0)
	if (g_query.find('=') == g_query.npos)
	{
		size_t p_1 = 0;
		for (size_t p = 0; p < g_query.size(); ++p) {
			if (g_query[p] == '+') {
				// g_query[p_1 .. p) => decoded
				std::string_view q = std::string_view(g_query).substr(p_1, p_1 - p);
				std::string q_out(q.size(), '\0');
				size_t z = strdecode(q_out, q);
				q_out.resize(z);
				argp.push_back(q_out);

				p_1 = p + 1;
			}
		}
		//for (cp1 = cp2 = query; *cp2 != '\0'; ++cp2)
		//{
		//	if (*cp2 == '+')
		//	{
		//		*cp2 = '\0';
		//		strdecode(cp1, cp1);
		//		argp[argn++] = cp1;
		//		cp1 = cp2 + 1;
		//	}
		//}
		if (p_1 < g_query.size())
		{
		//	strdecode(cp1, cp1);
		//	argp[argn++] = cp1;
			std::string_view q = std::string_view(g_query).substr(p_1);
			std::string q_out(q.size(), '\0');
			size_t z = strdecode(q_out, q);
			q_out.resize(z);
			argp.push_back(q_out);
		}
	}

	//argp[argn] = (char*)0;
	return argp;
}

/* Set up CGI environment variables. Be real careful here to avoid
** letting malicious clients overrun a buffer.  We don't have
** to worry about freeing stuff since we're a sub-process.
*/
static std::vector<std::string> make_envp(void)
{
	//static char* envp[50];
	//int envn;
	const char* cp;
	//char buf[256];
	
	std::vector<std::string>envp(50);

	size_t envn = 0;
	envp[envn++] = std::format("PATH={}", CGI_PATH);
	envp[envn++] = std::format("LD_LIBRARY_PATH={}", CGI_LD_LIBRARY_PATH);
	envp[envn++] = std::format("SERVER_SOFTWARE={}", SERVER_SOFTWARE);
	
	if (!g_vhost)
		cp = g_hostname;
	else
		cp = g_req_hostname.c_str();	/* already computed by virtual_file() */
	
	if (cp != nullptr && *cp != '\0')
		envp[envn++] = std::format("SERVER_NAME={}", cp);
	envp[envn++] = "GATEWAY_INTERFACE=CGI/1.1";
	envp[envn++] = "SERVER_PROTOCOL=HTTP/1.0";
	//(void)snprintf(buf, sizeof(buf), "%d", g_port);
	envp[envn++] = std::format("SERVER_PORT={}", g_port);
	envp[envn++] = std::format(
		"REQUEST_METHOD={}", get_method_str(g_method));
	envp[envn++] = std::format("SCRIPT_NAME={}", g_path);
	if (g_query[0] != '\0')
		envp[envn++] = std::format("QUERY_STRING={}", g_query);
	envp[envn++] = std::format("REMOTE_ADDR={}", ntoa(&g_client_addr));
	if (g_referer[0] != '\0')
		envp[envn++] = std::format("HTTP_REFERER={}", g_referer);
	if (g_useragent[0] != '\0')
		envp[envn++] = std::format("HTTP_USER_AGENT={}", g_useragent);
	if (g_cookie != nullptr)
		envp[envn++] = std::format("HTTP_COOKIE={}", g_cookie);
	if (g_content_type != nullptr)
		envp[envn++] = std::format("CONTENT_TYPE={}", g_content_type);
	if (g_content_length != -1)
	{
		//(void)snprintf(buf, sizeof(buf), "%ld", content_length);
		envp[envn++] = std::format("CONTENT_LENGTH={}", g_content_length);
	}
	if (g_remoteuser.size() > 0 )
		envp[envn++] = std::format("REMOTE_USER={}", g_remoteuser);
	if (g_authorization.size() > 0 )
		envp[envn++] = std::format("AUTH_TYPE={}", "Basic");
	if (getenv("TZ") != nullptr)
		envp[envn++] = std::format("TZ={}", getenv("TZ"));

	//envp[envn] = (char*)0;
	envp.resize(envn);
	return envp;
}




//static char* build_env(char* fmt, char* arg)
//{
//	char* cp;
//	int size;
//	static char* buf;
//	static int maxbuf = 0;
//
//	size = strlen(fmt) + strlen(arg);
//	if (size > maxbuf)
//	{
//		if (maxbuf == 0)
//		{
//			maxbuf = 256;
//			buf = (char*)malloc(maxbuf);
//		}
//		else
//		{
//			maxbuf *= 2;
//			buf = (char*)realloc((void*)buf, maxbuf);
//		}
//		if (buf == (char*)0)
//		{
//			(void)fprintf(stderr, "%s: out of memory\n", g_argv0);
//			exit(1);
//		}
//	}
//	(void)snprintf(buf, maxbuf, fmt, arg);
//	cp = strdup(buf);
//	if (cp == (char*)0)
//	{
//		(void)fprintf(stderr, "%s: out of memory\n", g_argv0);
//		exit(1);
//	}
//	return cp;
//}



static void auth_check(const std::string& dirname)
{
	//char authpath[10000];
	//struct stat sb;
	//char authinfo[500];
	//char* authpass;
	//static char line[10000];
	//int l;
	//FILE* fp;
	//char* cryp;

	std::string authpath;
	/* Construct auth filename. */
	if ( dirname.ends_with('/') )
	{
		//(void)snprintf(authpath, sizeof(authpath), "%s%s", dirname, AUTH_FILE);
		authpath = std::format("{}{}", dirname, AUTH_FILE);
	}
	else
	{
		//(void)snprintf(authpath, sizeof(authpath), "%s/%s", dirname, AUTH_FILE);
		authpath = std::format("{}/{}", dirname, AUTH_FILE);
	}

	/* Does this directory have an auth file? */
	namespace fs = std::filesystem;
	
	fs::path fs_authpath(authpath);
	

	//if (stat(authpath, &sb) < 0)
	//	/* Nope, let the request go through. */
	//	return;
	std::error_code ec{};
	const auto status = fs::status(fs_authpath, ec);
	
	if (ec)
	{
		//нельзя получит информация. пускай продолжается запрос ( но почему?? )
		return;
	}
	
	/* Does this request contain authorization info? */
	if (g_authorization.empty())
	{
		/* Nope, return a 401 Unauthorized. */
		send_authenticate(dirname);
	}

	/* Basic authorization info? */
	//if (strncmp(authorization, "Basic ", 6) != 0)
	//	send_authenticate(dirname);
	
	using namespace std::literals::string_view_literals;
	if (!g_authorization.starts_with("Basic "sv)) {
		//supported only Basic authorization.
		send_authenticate(dirname);
	}

	/* Decode it. */
	//std::span<unsigned char> authinfo_out{ reinterpret_cast<unsigned char*>(authinfo), sizeof(authinfo) };

	std::string authinfo = b64_decode(std::string_view(g_authorization).substr(6));
	
	//authinfo[l_auth] = '\0';
	
	/* Split into user and password. */
	
	std::string authpass;
	if (std::size_t pos = authinfo.find(':'); pos != authinfo.npos) {
		authpass = authinfo.substr(pos+1);
		authinfo = authinfo.substr(0, pos);
	}
	else {
		/* No colon?  Bogus auth info. */
		send_authenticate(dirname);
	}
	//authpass = strchr(authinfo, ':');
	//
	//if (authpass == nullptr)
	//{
	//	/* No colon?  Bogus auth info. */
	//	send_authenticate(dirname);
	//}
	//*authpass++ = '\0';

	/* Open the password file. */
	//fp = fopen(authpath.c_str(), "r");
	std::ifstream fp(authpath);
	if (!fp.is_open())
	{
		/* The file exists but we can't open it?  Disallow access. */
		send_error(403, "Forbidden", nullptr, "File is protected.");
	}

	std::string line;
	/* Read it. */
	//while (fgets(line, sizeof(line), fp) != nullptr)
	while (std::getline(fp, line))
	{
		/* Nuke newline. */
		size_t l = line.size();
		if (line.ends_with('\n'))
			line.pop_back();
		
		/* Split into user and encrypted password. */
		size_t cryp_pos = line.find(':');
		if (cryp_pos == line.npos)
			continue;

		//cryp = strchr(line, ':');
		//if (cryp == nullptr)
		//	continue;

		//*cryp++ = '\0';
		
		/* Is this the right user? */
		
		//if (strcmp(line, authinfo) == 0)
		std::string_view line_view = line;
		std::string_view cryp_view = line_view.substr(0, cryp_pos);
		std::string_view auth_view(authinfo);

		if (cryp_view == auth_view)
		{
			/* Yes. */
			//(void)fclose(fp);
			fp.close();
	
			/* So is the password right? */
			std::string cryp(cryp_view);
			if (strcmp(crypt(authpass.c_str(), cryp.c_str()), cryp.c_str()) == 0)
			{
				/* Ok! */
				g_remoteuser = line;
				return;
			}
			else
			{	
				/* No. */
				send_authenticate(dirname);
			}
		}
	}

	/* Didn't find that user.  Access denied. */
	
	send_authenticate(dirname);
}



static void send_authenticate(const std::string_view realm)
{
	//char header[10000];

	//(void)snprintf(
	//	header, sizeof(header), "WWW-Authenticate: Basic realm=\"%s\"", realm);
	
	std::string header = std::format("WWW-Authenticate: Basic realm=\"{}\"", realm);
	
	send_error(401, "Unauthorized", header.c_str(), "Authorization required.");
}


static std::string virtual_file(const char* file)
{
	//char* cp;
	//static char vfile[10000];

	/* Use the request's hostname, or fall back on the IP address. */
	if (g_host.size() > 0)
	{
		g_req_hostname = g_host;
	}
	else
	{
		usockaddr usa{};

		int sz = sizeof(usa);
		if (getsockname(g_conn_fd, &usa.sa, &sz) < 0)
			g_req_hostname = "UNKNOWN_HOST";
		else
			g_req_hostname = ntoa(&usa);
	}
	/* Pound it to lower case. */
	for (char& cp : g_req_hostname)
	{
		if (isupper(cp))
		{
			cp = tolower(cp);
		}
	}

	//(void)snprintf(vfile, sizeof(vfile), "%s/%s", g_req_hostname, file);
	//return vfile;
	return std::format("{}/{}", g_req_hostname, file);
}



static void send_error(int s, const char* title, const char* extra_header, const char* text)
{
	add_headers(s, title, extra_header, "text/html", -1, -1);

	send_error_body(s, title, text);

	send_error_tail();

	send_response();

#ifdef USE_SSL
	SSL_free(ssl);
#endif /* USE_SSL */
	
	//@TODO: replace it to throw exception.
	exit(1);
}




static void send_error_body(int s, const char* title, const char* text)
{
	//char filename[1000];
	//char buf[10000];
	//int buflen;

	if (g_vhost != 0 && g_req_hostname.size() > 0)
	{
		/* Try virtual-host custom error page. */
		//(void)snprintf(
		//	filename, sizeof(filename), "%s/%s/err%d.html",
		//	g_req_hostname, ERR_DIR, s);
		std::string filename = std::format("{}/{}/err{}.html", g_req_hostname, ERR_DIR, s);

		if (send_error_file(filename.c_str()))
			return;
	}

	/* Try server-wide custom error page. */
	{
		//(void)snprintf(filename, sizeof(filename), "%s/err%d.html", ERR_DIR, s);
		std::string filename = std::format("{}/err{}.html", ERR_DIR, s);
		if (send_error_file(filename.c_str()))
			return;
	}

	/* Send built-in error page. */
	//buflen = snprintf(
	//	buf, sizeof(buf),
	//	"<HTML><HEAD><TITLE>%d %s</TITLE></HEAD>\n<BODY BGCOLOR=\"#cc9999\"><H4>%d %s</H4>\n",
	//	s, title, s, title);

	std::string buf = std::format("<HTML><HEAD><TITLE>{0} {1}</TITLE></HEAD>\n<BODY BGCOLOR=\"#cc9999\"><H4>{0} {1}</H4>", s, title);

	add_to_response(buf);
	//buflen = snprintf(buf, sizeof(buf), "%s\n", text);
	buf = std::format("{}\n", text);
	add_to_response(buf);
}



static bool send_error_file(const char* filename)
{
	FILE* fp;
	char buf[1024];
	

	fp = fopen(filename, "r");
	if (fp == nullptr)
	{
		return false;
	}

	struct scoped_exit_close_t
	{
		FILE* f;

		~scoped_exit_close_t() {
			(void)fclose(f);
		}
	};
	const scoped_exit_close_t close_scoped{ fp };

	while(true)
	{
		size_t r = fread(buf, sizeof(char), sizeof(buf)/sizeof(char), fp);
		
		if (r == 0)
			break;

		//this may throw std::bad_alloc.
		add_to_response(std::string_view{ buf, r });
	}
	
	
	return true;
}


static void send_error_tail(void)
{
	//char buf[500];
	//int buflen;
	
	using namespace std::literals::string_view_literals;

	if (match("**MSIE**"sv, g_useragent))
	{
		//int n;
		//buflen = snprintf(buf, sizeof(buf), "<!--\n");
		
		std::string buf = "<!--\n";
		add_to_response(buf);

		for (int n = 0; n < 6; ++n)
		{
			std::string_view buf_view = "Padding so that MSIE deigns to show this error instead of its own canned one.\n";
			add_to_response(buf_view);
		}
		//buflen = snprintf(buf, sizeof(buf), "-->\n");
		buf = "-->\n";
		add_to_response(buf);
	}

	//buflen = snprintf(buf, sizeof(buf), "<HR>\n<ADDRESS><A HREF=\"%s\">%s</A></ADDRESS>\n</BODY></HTML>\n", SERVER_URL, SERVER_SOFTWARE);
	std::string buf = std::format("<HR>\n<ADDRESS><A HREF=\"{}\">{}</A></ADDRESS>\n</BODY></HTML>\n", SERVER_URL, SERVER_SOFTWARE);
	add_to_response(buf);
}


static void add_headers(int s, const char* title, const char* extra_header, const char* mime_type, long b, time_t mod)
{
	time_t now;
	char timebuf[100];
	//char buf[10000];
	//int buflen;
	const char* rfc1123_fmt = "%a, %d %b %Y %H:%M:%S GMT";

	g_status = s;
	g_bytes = b;

	make_log_entry();
	start_response();
	
	std::string buf = std::format("{} {} {}\r\n", g_protocol, g_status, title);
	//buflen = snprintf(buf, sizeof(buf), "%s %d %s\r\n", g_protocol, g_status, title);
	
	add_to_response(buf);

	//buflen = snprintf(buf, sizeof(buf), "Server: %s\r\n", SERVER_SOFTWARE);
	buf = std::format("Server: {}\r\n", SERVER_SOFTWARE);
	add_to_response(buf);

	now = time(nullptr);
	struct tm local_tm {};
	gmtime_s(&local_tm, &now);
	(void)strftime(timebuf, sizeof(timebuf), rfc1123_fmt, &local_tm);

	//buflen = snprintf(buf, sizeof(buf), "Date: %s\r\n", timebuf);
	buf = std::format("Date: {}\r\n", timebuf);

	add_to_response(buf);

	if (extra_header != nullptr)
	{
		//buflen = snprintf(buf, sizeof(buf), "%s\r\n", extra_header);
		buf = std::format("{}\r\n", extra_header);
		add_to_response(buf);
	}

	if (mime_type != nullptr)
	{
		//buflen = snprintf(buf, sizeof(buf), "Content-type: %s\r\n", mime_type);
		buf = std::format("Content-type: {}\r\n", mime_type);
		add_to_response(buf);
	}
	if (g_bytes >= 0)
	{
		//buflen = snprintf(buf, sizeof(buf), "Content-length: %ld\r\n", bytes);
		buf = std::format("Content-length: {}\r\n", g_bytes);
		add_to_response(buf);
	}
	if (mod != (time_t)-1)
	{
		struct tm local_tm {};
		gmtime_s(&local_tm, &mod);
		(void)strftime(timebuf, sizeof(timebuf), rfc1123_fmt, &local_tm);
		//buflen = snprintf(buf, sizeof(buf), "Last-modified: %s\r\n", timebuf);
		buf = std::format("Last-modified: {}\r\n", timebuf);
		add_to_response(buf);
	}
	//buflen = snprintf(buf, sizeof(buf), "Connection: close\r\n\r\n");
	buf = std::format("Connection: close\r\n\r\n");
	add_to_response(buf);
}



static void start_request(void)
{
	g_request = "";
	g_request_idx = 0;
}

static void add_to_request( const std::string_view str )
{
	add_to_buf(g_request, str);
}




static std::string_view get_request_line(void)
{
	int i;
	char c;

	for (i = g_request_idx; g_request_idx < g_request.length(); ++g_request_idx)
	{
		c = g_request[g_request_idx];
		if (c == '\n' || c == '\r')
		{
			int end_idx = g_request_idx;
			g_request[g_request_idx] = '\0';

			++g_request_idx;

			if (c == '\r' && g_request_idx < g_request.length() &&
				g_request[g_request_idx] == '\n')
			{
				g_request[g_request_idx] = '\0';
				++g_request_idx;
			}
			
			// should return g_request[i .. end_idx)
			return std::string_view(g_request).substr(i, end_idx - i);
			//return &(g_request[i]);

		}
	}
	return std::string_view{};
}



static void start_response(void)
{
	g_response = "";
}

static void add_to_response( const std::string_view str)
{
	add_to_buf(g_response, str);
}


static void send_response(void)
{
	(void)my_write(g_response);
}



static int my_read(const std::span<char> buf)
{
#ifdef USE_SSL
	if (do_ssl)
		return SSL_read(ssl, buf, size);
	else
		return read(conn_fd, buf, size);
#else /* USE_SSL */

#ifndef _WIN32
	return read(g_conn_fd, buf.data(), (unsigned int)buf.size());
#else 
	constexpr int no_flags = 0;
	return recv( g_conn_fd, buf.data(), static_cast<int>(buf.size_bytes()), no_flags );
#endif //!_WIN32

#endif /* USE_SSL */
}


static int my_write(const std::string_view buf)
{
#ifdef USE_SSL
	if (do_ssl)
		return SSL_write(ssl, buf, size);
	else
		return write(conn_fd, buf, size);
#else /* USE_SSL */

#ifndef _WIN32
	return write(g_conn_fd, buf.data(), (unsigned int)buf.size());
#else 
	constexpr int no_flag = 0;
	return send(g_conn_fd, buf.data(), static_cast<int>(buf.size()), no_flag);
#endif //!_WIN32
#endif /* USE_SSL */
}


static void add_to_buf  (std::string& bufP, const std::string_view str)
//(char** bufP, int* bufsizeP, int* buflenP, char* str, int len)
{
	bufP.append(str.begin(), str.end());
	/*if (*bufsizeP == 0)
	{
		*bufsizeP = len + 500;
		*buflenP = 0;
		*bufP = (char*)malloc(*bufsizeP);
	}
	else if (*buflenP + len >= *bufsizeP)
	{
		*bufsizeP = *buflenP + len + 500;
		*bufP = (char*)realloc((void*)*bufP, *bufsizeP);
	}
	
	if (*bufP == nullptr)
	{
		(void)fprintf(stderr, "%s: out of memory\n", g_argv0);
		exit(1);
	}
	
	(void)memcpy(&((*bufP)[*buflenP]), str, len);
	*buflenP += len;
	(*bufP)[*buflenP] = '\0';*/

}



static long get_timezone_offset_minutes(time_t t)
{
	struct tm local_tm{};
	struct tm utc_tm{};

	localtime_s(&local_tm, &t);
	gmtime_s(&utc_tm, &t);

	// mktime(local) трактует local_tm как local time.
	// _mkgmtime(utc) трактует utc_tm как UTC.
	
	const time_t lt = mktime(&local_tm);
	const time_t ut = _mkgmtime(&utc_tm);

	return static_cast< long >( difftime(lt, ut	) / 60 );
}


static void make_log_entry(void)
{
	const char* ru;
	//char url[ 500 ];
	//char bytes_str[ 40 ];
	std::string bytes_str;
	std::string url;

	time_t now;
	
	struct tm local_tm{};
	
	const char* cernfmt_nozone = "%d/%b/%Y:%H:%M:%S";

	char date_nozone[100];
	int zone;
	char sign;
	char date[100];

	if (g_logfp == nullptr)
	{
		return;
	}

	/* Format the user. */
	if (g_remoteuser.size() > 0)
		ru = g_remoteuser.c_str();
	else
		ru = "-";

	now = time(nullptr);
	/* If we're vhosting, prepend the hostname to the url.  This is
	** a little weird, perhaps writing separate log files for
	** each vhost would make more sense.
	*/
	if (g_vhost != 0)
	{
		//(void)snprintf(url, sizeof(url), "/%s%s", g_req_hostname, g_path);
		url = std::format("/{}{}", g_req_hostname, g_path);
	}
	else
	{
		//(void)snprintf(url, sizeof(url), "%s", g_path);
		url = std::format("{}", g_path);
	}

	/* Format the bytes. */
	if (g_bytes >= 0)
	{
		//(void)snprintf(bytes_str, sizeof(bytes_str), "%ld", g_bytes);
		bytes_str = std::to_string(g_bytes);
	}
	else
	{
		//(void)strcpy(bytes_str, "-");
		bytes_str = "-";
	}

	/* Format the time, forcing a numeric timezone (some log analyzers
	** are stoooopid about this).
	*/
	localtime_s(&local_tm, &now);

	(void)strftime(date_nozone, sizeof(date_nozone), cernfmt_nozone, &local_tm);
	
#ifdef HAVE_TM_GMTOFF
	zone = local_tm.tm_gmtoff / 60L;
#else
	zone = zone = get_timezone_offset_minutes(now);  //-(timezone / 60L);
	/* Probably have to add something about daylight time here. */
#endif

	if (zone >= 0)
		sign = '+';
	else
	{
		sign = '-';
		zone = -zone;
	}
	zone = (zone / 60) * 100 + zone % 60;

	(void)snprintf(date, sizeof(date), "%s %c%04d", date_nozone, sign, zone);
	
	/* And write the log entry. */
	(void)fprintf(g_logfp,
		"%.80s - %.80s [%s] \"%.80s %.200s %.80s\" %d %s \"%.200s\" \"%.80s\"\n",
		ntoa(&g_client_addr).c_str(), ru, date, get_method_str(g_method), url.c_str(),
		g_protocol, g_status, bytes_str.c_str(), g_referer, g_useragent.c_str());

	(void)fflush(g_logfp);
}


//@NOTE: replace it to enum class HttpMethod{  GET, HEAD, POST, PUT };
static const char* get_method_str(int m)
{
	switch (m)
	{
	case METHOD_GET: return "GET";
	case METHOD_HEAD: return "HEAD";
	case METHOD_POST: return "POST";
	case METHOD_PUT: return "PUT";
	default: 
		return nullptr;
	}
}




static const char* get_mime_type(const char* name)
{
	struct MimeType 
	{
		const char* ext;
		const char* type;
	};
	
	static constexpr MimeType table[] = 
	{
	
#include "mime_types.h"

	};
	
	const size_t fl = strlen(name);
	

	for (const MimeType mimeType : table)
	{
		const size_t el = strlen(mimeType.ext);
		
		if (el <= fl && strcasecmp(&(name[fl - el]), mimeType.ext) == 0)
		{
			return mimeType.type;
		}
	}

	return "text/plain; charset=%s";
}



static void handle_sigterm(int sig)
{
	(void)fprintf(stderr, "%s: exiting due to signal %d\n", g_argv0, sig);
	exit(1);
}

//static void
//handle_sigchld(int sig)
//{
//	pid_t pid;
//	int status;
//
//	/* Reap defunct children until there aren't any more. */
//	for (;;)
//	{
//#ifdef HAVE_WAITPID
//		pid = waitpid((pid_t)-1, &status, WNOHANG);
//#else /* HAVE_WAITPID */
//		pid = wait3(&status, WNOHANG, (struct rusage*)0);
//#endif /* HAVE_WAITPID */
//		if ((int)pid == 0)		/* none left */
//			break;
//		if ((int)pid < 0)
//		{
//			if (errno == EINTR)	/* because of ptrace */
//				continue;
//			/* ECHILD shouldn't happen with the WNOHANG option,
//			** but with some kernels it does anyway.  Ignore it.
//			*/
//			if (errno != ECHILD)
//				perror("child wait");
//			break;
//		}
//	}
//}



static lookup_result_t lookup_hostname(
							std::span<usockaddr> usa4P, 
							std::span<usockaddr> usa6P 
							)
{
#if defined(HAVE_GETADDRINFO) && defined(HAVE_GAI_STRERROR)

	lookup_result_t result{};

	struct addrinfo hints {};

	struct addrinfo* ai;
	struct addrinfo* ai2;
	struct addrinfo* aiv4;
	struct addrinfo* aiv6;
	int gaierr;
	
	//char strport[10];

	//memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;
	
	//(void)snprintf(strport, sizeof(strport), "%d", g_port);
	
	std::string strport = std::to_string(g_port);
	
	if ((gaierr = getaddrinfo(g_hostname, strport.c_str(), &hints, &ai)) != 0)
	{
		(void)fprintf(stderr, "getaddrinfo %.80s - %s\n", g_hostname, gai_strerror(gaierr));
		exit(1);
	}
	
	struct scoped_exit_freeaddrinfo_t
	{
		struct addrinfo* ai_;
		~scoped_exit_freeaddrinfo_t() {
			freeaddrinfo(ai_);
		}
	};
	const scoped_exit_freeaddrinfo_t scoped_exit_freeaddrinfo{ ai };

	/* Find the first IPv4 and IPv6 entries. */
	aiv4 = nullptr;
	aiv6 = nullptr;
	for (ai2 = ai; ai2 != nullptr; ai2 = ai2->ai_next)
	{
		switch (ai2->ai_family)
		{
		case AF_INET:
			if (aiv4 == nullptr) // take first IP v4
				aiv4 = ai2;
			break;
#if defined(AF_INET6) && defined(HAVE_SOCKADDR_IN6)
		case AF_INET6:
			if (aiv6 == nullptr) // take first IP v6
				aiv6 = ai2;
			break;
#endif /* AF_INET6 && HAVE_SOCKADDR_IN6 */
		}
	}


	if (aiv4 == nullptr)
	{
		result.gotv4P = false;
	}
	else
	{
		if (usa4P.size_bytes() < aiv4->ai_addrlen)
		{
			(void)fprintf(
				stderr, "%.80s - sockaddr too small (%zu < %zu)\n",
				g_hostname, usa4P.size_bytes(), aiv4->ai_addrlen);
			exit(1);
		}

		//memset(usa4P.data(), 0, usa4P.size_bytes());
		std::ranges::fill(usa4P, usockaddr{});

		memcpy(usa4P.data(), aiv4->ai_addr, aiv4->ai_addrlen);
		
		result.gotv4P = true;
	}
	
	if (aiv6 == nullptr)
	{
		result.gotv6P = false;
	}
	else
	{
		if (usa6P.size_bytes() < aiv6->ai_addrlen)
		{
			(void)fprintf(
				stderr, "%.80s - sockaddr too small (%zu < %zu)\n",
				g_hostname, usa6P.size_bytes(), aiv6->ai_addrlen);
			exit(1);
		}
		
		//memset(usa6P.data(), 0, usa6P.size_bytes());
		std::ranges::fill(usa6P, usockaddr{});

		//memcpy не будем менять, иначе код станет вообще не читаемой.
		memcpy(usa6P.data(), aiv6->ai_addr, aiv6->ai_addrlen);

		result.gotv6P = true;
	}

	
	return result;
#else /* HAVE_GETADDRINFO && HAVE_GAI_STRERROR */

	struct hostent* he;

	*gotv6P = 0;

	memset(usa4P, 0, sa4_len);

	usa4P->sa.sa_family = AF_INET;

	if (g_hostname == nullptr)
	{
		usa4P->sa_in.sin_addr.s_addr = htonl(INADDR_ANY);
	}
	else
	{
		usa4P->sa_in.sin_addr.s_addr = inet_addr(g_hostname);
		if ((int)usa4P->sa_in.sin_addr.s_addr == -1)
		{
			he = gethostbyname(g_hostname);
			if (he == nullptr)
			{
	#ifdef HAVE_HSTRERROR
				(void) fprintf(stderr, "gethostbyname %.80s - %s\n", g_hostname, hstrerror(h_errno));
	#else /* HAVE_HSTRERROR */
				(void)fprintf(stderr, "gethostbyname %.80s failed\n", g_hostname);
	#endif /* HAVE_HSTRERROR */
				exit(1);
			}
			if (he->h_addrtype != AF_INET)
			{
				(void)fprintf(stderr, "%.80s - non-IP network address\n", g_hostname);
				exit(1);
			}
			(void)memcpy(
				&usa4P->sa_in.sin_addr.s_addr, he->h_addr, he->h_length);
		}
	}
	usa4P->sa_in.sin_port = htons(g_port);
	*gotv4P = 1;

#endif /* HAVE_GETADDRINFO && HAVE_GAI_STRERROR */
}


static std::string ntoa(usockaddr* usaP)
{
#ifdef HAVE_GETNAMEINFO
	char str[200] = {'\0'};

	if (getnameinfo(&usaP->sa, sockaddr_len(usaP), str, sizeof(str), 0, 0, NI_NUMERICHOST) != 0)
	{
		str[ 0 ] = '?';
		str[ 1 ] = '\0';
	}

	return std::string( str ) ;

#else /* HAVE_GETNAMEINFO */

	return inet_ntoa(usaP->sa_in.sin_addr);

#endif /* HAVE_GETNAMEINFO */
}



static socklen_t sockaddr_len(usockaddr* usaP)
{
	switch (usaP->sa.sa_family)
	{
	case AF_INET: return sizeof(struct sockaddr_in);
#if defined(AF_INET6) && defined(HAVE_SOCKADDR_IN6)
	case AF_INET6: return sizeof(struct sockaddr_in6);
#endif /* AF_INET6 && HAVE_SOCKADDR_IN6 */
	default:
		(void)fprintf(
			stderr, "unknown sockaddr family - %d\n", usaP->sa.sa_family);
		exit(1);
	}
}



static constexpr bool is_xdigit(char c) noexcept
{
	return (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F');
}

/* Copies and decodes a string.  It's ok for from and to to be the
** same string.
*/
static size_t strdecode(std::span<char> to, std::span<const char> from)
{
	size_t z = 0;

	for (size_t i = 0; i < from.size() && z < to.size(); i++)
	{
		if (from[i] == '%') 
		{
			if (i + 2 < from.size() && is_xdigit(from[i + 1]) && is_xdigit(from[i + 2])) 
			{
				to[z++] =  (hexit(from[i + 1]) << 4) | hexit(from[i + 2]);
			}
			else 
			{
				//what if there no more digits '%1'  or '%' itself ?

				to[z++] = from[i];
			}
		}
		else 
		{
			to[z++] = from[i];
		}
	}
	
	if (z < to.size()) 
	{
		to[z++] = '\0';
	}
	return z;
}



static int hexit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	
	return 0;           /* shouldn't happen, we're guarded by isxdigit() */
}


/* Base-64 decoding.  This represents binary data as printable ASCII
** characters.  Three 8-bit binary bytes are turned into four 6-bit
** values, like so:
**
**   [11111111]  [22222222]  [33333333]
**
**   [111111] [112222] [222233] [333333]
**
** Then the 6-bit values are represented using the characters "A-Za-z0-9+/".
*/

static constexpr int b64_decode_table[256] = 
{
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 00-0F */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 10-1F */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  /* 20-2F */
	52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,  /* 30-3F */
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  /* 40-4F */
	15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  /* 50-5F */
	-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  /* 60-6F */
	41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  /* 70-7F */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 80-8F */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 90-9F */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* A0-AF */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* B0-BF */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* C0-CF */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* D0-DF */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* E0-EF */
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1   /* F0-FF */
};

enum class B64_Phases
{
	start, phase_1, phase_2, phase_3
};

/* Do base-64 decoding on a string.  Ignore any non-base64 bytes.
** Return the actual number of bytes generated.  The decoded size will
** be at most 3/4 the size of the encoded, and may be smaller if there
** are padding characters (blanks, newlines).
*/
static std::string b64_decode(std::string_view str)
{
	//size_t space_idx = 0;
	std::string result;
	result.reserve(str.size() / 4 * 3);

	enum B64_Phases phase = B64_Phases::start;

	int prev_d = -1;

	//specially use unsigned char, not char.
	for (const unsigned char cp : str)
	{
		const int d = b64_decode_table[cp];
		if (d != -1)
		{
			switch (phase)
			{
			case B64_Phases::start:
				phase = B64_Phases::phase_1;
				break;
			case B64_Phases::phase_1:
			{
				const unsigned char c = ((prev_d << 2) | ((d & 0x30) >> 4));
				
				//if (space_idx < space.size())
				//	space[space_idx++] = c;
				result += (char)c;
				
				phase = B64_Phases::phase_2;
			}
			break;
			case B64_Phases::phase_2:
			{
				const unsigned char c = (((prev_d & 0xf) << 4) | ((d & 0x3c) >> 2));
				
				//if (space_idx < space.size())
				//	space[space_idx++] = c;
				result += (char)c;
				
				phase = B64_Phases::phase_3;
			}
			break;
			case B64_Phases::phase_3:
			{
				const unsigned char c = (((prev_d & 0x03) << 6) | d);
				
				//if (space_idx < space.size())
				//	space[space_idx++] = c;
				result += (char)c;
				
				phase = B64_Phases::start;
			}
			break;
			}
			prev_d = d;
		}
	}
	return result;
}


/* Simple shell-style filename matcher.  Only does ? * and **, and multiple
** patterns separated by |.  Returns 1 or 0.
*/
static bool match(std::string_view pattern, std::string_view  string)
{
	while (!pattern.empty())
	{
		const size_t pos = pattern.find('|');
		
		if (pos == pattern.npos)
			return match_one(pattern, string);

		if (match_one(pattern.substr(0, pos), string))
			return true;
		
		pattern.remove_prefix(pos + 1);
	}

	//if pattern empty so string must be also empty.
	return string.empty();
}




static bool match_empty(std::string_view pattern) 
{
	//matched to empty string.
	for (const char c : pattern) 
	{
		if (c != '*')
			return false;
	}
	return true;
}

static bool match_literal(const std::string_view pattern, const std::string_view str)
{
	if (pattern.length() != str.length())
		return false;
	for (size_t p = 0; p < pattern.size(); p++) {
		if (pattern[p] != '?' && pattern[p] != str[p])
			return false;
	}
	return true;
}



static bool match_one(std::string_view pattern, std::string_view str)
{

	const size_t pos_star = pattern.find('*');

	if (pos_star == pattern.npos) {
		// whole pattern is literal
		return match_literal(pattern, str);
	}

	// a special case
	if (str.empty())
		return match_empty(pattern);

	//1. match  pattern[0..pos_star)  with str[0 .. pos_star)
	if (!match_literal(pattern.substr(0, pos_star), str.substr(0, pos_star)))
	{
		return false;
	}

	//2. double '**' case: it matched anything.
	if (pos_star + 1 < pattern.size() && pattern[pos_star + 1] == '*') {
		
		for (size_t i = str.size(); ; --i) {

			if (match_one(pattern.substr(pos_star + 2), str.substr(i)))
				return true;

			if (i == 0)
				break;
		}
		return false;
	}

	//3. single '*' case: it matched until '/' symbol
	for (size_t i = std::min(str.size(), str.find('/')); ; --i)
	{
		if (match_one(pattern.substr(pos_star + 1), str.substr(i)))
			return true;

		if (i == 0)
			break;
	}
	return false;
}


