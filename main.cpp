#include <sqlite3.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <map>
#include <queue>
#include <cerrno>
#include <fstream>
#include <sstream>
#include <memory>
#include <chrono>
#include <mutex>

#include <boost/beast/core/detail/base64.hpp>


enum
{
    BACKLOG = 10,
    RECV_BUF_SZ = 32768,

    GET,
    POST,
    OPTIONS,
    NOT_SUPPORTED,

    HTML,
    CSS,
    CSV,
    JS,
    XML,
    JPEG,
    PNG,
    GIF,
    WEBP,
};


std::mutex login_db_mutex;
std::mutex msg_db_mutex;

static std::map<const std::string, std::mutex*> DB_MUTEX{{"login.db", &login_db_mutex}, {"messages.db", &msg_db_mutex}};

#define CHECK_ACCESS_QUERY(login, password) ("SELECT DISTINCT * FROM auth_users WHERE user_login = \"" + login + "\" AND user_password = \"" + passwd + "\";")
#define SEND_MSG_QUERY(msgID, msgDate, msgAuthor, msgContent) ("INSERT INTO messages VALUES (" + msgID + ",\"" + msgDate + "\",\"" + msgAuthor + "\", \"" + msgContent + "\");")


static int 
login_callback_function(void* nu, int argc, char **argv, char **azColName)
{
    int *entries_n_p = (int*) nu;
    ++(*entries_n_p);

    return 0;
}

static int
msg_callback_function(void* nu, int argc, char **argv, char **azColName)
{
    std::vector<std::string> *msgs = (std::vector<std::string>*) nu;

    std::string tmp = "";

    for (int i = 0; i < argc; ++i) {
        tmp += std::string(argv[i]) + ((i + 1 < argc) ? " | " : "<br>");
    }

    (*msgs).push_back(tmp);
    return 0;
}

std::string 
decode_Base64(std::string& byte_seq)
{
    char *buf = new char[byte_seq.size()];
    memset(buf, 0, byte_seq.size());

    boost::beast::detail::base64::decode(buf, byte_seq.c_str(), byte_seq.size());
    std::string out(buf);

    delete buf;
    return out;
}


namespace http
{
    static std::map<const std::string, int> METHODS{{"GET", GET}, {"POST", POST}, {"OPTIONS", OPTIONS}};
    static std::map<const std::string, int> FILE_EXTS{{"html", HTML}, {"css", CSS}, {"csv", CSV}, 
            {"js", JS}, {"xml", XML}, {"jpeg", JPEG}, {"jpg", JPEG}, {"png", PNG}, {"gif", GIF}, {"webp", WEBP}};

    struct Request
    {
        int method;
        std::string address;
        std::string protocol;
        std::string protocol_ver;
        std::string host;
        std::string user_agent;
        std::string content_type;
        int content_len;
        std::string content;
        std::string user_key;

        Request(std::string& req_str);
    };

    Request::Request(std::string& req_str) : content("")
    {
        std::stringstream ss(req_str);
        std::string tmp;
        char tmp_ch;

        ss >> tmp >> address;

        if (http::METHODS.count(tmp)) {
            method = http::METHODS[tmp];
        } else {
            method = NOT_SUPPORTED;
        }

        ss >> tmp;
        int found = tmp.find("/");
        protocol = tmp.substr(0, found);
        protocol_ver = tmp.substr(found + 1);

        ss.get();
        ss.get();

        while (std::getline(ss, tmp) && tmp != "" && tmp != "\r") {
            std::string header, params;
            int found = tmp.find(" ");

            if (found == tmp.npos) {
                content = std::move(tmp);
                return;
            }

            header = tmp.substr(0, found);
            params = tmp.substr(found + 1);

            if (header == "Host:") {
                host = params;
            } else if (header == "User-Agent:") {
                user_agent = params;
            } else if (header == "Content-Type:") {
                content_type = params;
            } else if (header == "Content-Length:") {
                content_len = stoi(params);
            } else if (header == "Authorization:") {
                found = params.find("Basic ");

                if (found != params.npos) {
                    user_key = params.substr(found + 6);
                    user_key.pop_back();
                }
            }
        }

        if (method == POST) {
            std::getline(ss, content);
        }
    }

    struct Response
    {
        std::string protocol;
        std::string protocol_ver;
        std::string status;
        std::string reason;
        std::string content_type;
        std::string content_len;
        std::string content;

        Response(const Request& req);

        std::string define_MIME(const std::string& address) const;

        bool check_access(const Request& req, const char *db_filename, std::string *parsed_login_p=nullptr);
        bool send_message(const Request& req, const char *db_filename, const std::string& author);
    };

    std::string 
    Response::define_MIME(const std::string& address) const
    {
        int found = address.rfind(".");

        if (found == address.npos) {
            return "";
        }

        std::string file_ext = address.substr(found + 1);
        for (auto& c : file_ext) c = tolower(c);

        switch (http::FILE_EXTS[file_ext])
        {
            case HTML: return "text/html";
            case CSS: return "text/css";
            case CSV: return "text/csv";
            case JS: return "text/javascript";
            case XML: return "text/xml";
            case JPEG: return "image/jpeg";
            case PNG: return "image/png";
            case GIF: return "image/gif";
            case WEBP: return "image/webp";
            default: return "";
        }
    }

    bool
    Response::check_access(const Request& req, const char *db_filename, std::string *parsed_login_p)
    {
        if (req.user_key.size() == 0) {
            status = "401";
            reason = "Unauthorized\nWWW-Authenticate: Basic";
            return false;
        } else {
            std::string userkey_nconst_cp = req.user_key;
            std::string dcoded = decode_Base64(userkey_nconst_cp);

            int delim_found = dcoded.find(":");

            std::string login, passwd;
            login = dcoded.substr(0, delim_found);
            passwd = dcoded.substr(delim_found + 1);

            if (parsed_login_p) {
                *parsed_login_p = login;
            }

            std::unique_lock<std::mutex> lk(*DB_MUTEX[db_filename]);

            sqlite3 *db;

            if (sqlite3_open(db_filename, &db)) {
                std::cerr << "SQLite3 open error: " << std::strerror(errno) << std::endl;
                status = "500";
                reason = "Internal Server Error";
                return false;
            }

            int entries_fnd = 0;

            sqlite3_exec(db, 
                    CHECK_ACCESS_QUERY(login, password).c_str(), 
                    login_callback_function, 
                    &entries_fnd, 
                    nullptr);

            sqlite3_close(db);

            if (entries_fnd == 1) {
                return true;
            } else {
                status = "401";
                reason = "Unauthorized\nWWW-Authenticate: Basic\n\n";
                return false;
            }
        }
    }

    bool
    Response::send_message(const Request& req, const char *db_filename, const std::string& author)
    {
        std::vector<std::string> messages;

        std::unique_lock<std::mutex> lk(*DB_MUTEX[db_filename]);

        sqlite3 *db;
        
        if (sqlite3_open(db_filename, &db)) {
            std::cerr << "SQLite3 open error: " << std::strerror(errno) << std::endl;
            status = "500";
            reason = "Internal Server Error";
            return false;
        }

        sqlite3_exec(db, "SELECT * FROM messages ORDER BY msgID DESC LIMIT 1;",
                msg_callback_function, &messages, nullptr);

        std::string last_msg = messages[0];
        std::string last_msg_id = std::to_string(std::stoi(last_msg.substr(0, last_msg.find(" |"))) + 1);

        std::time_t t = std::time(0);
        std::tm* now = std::localtime(&t);
        std::string msg_datetime = ((now->tm_mday <= 9) ? "0" : "") + std::to_string(now->tm_mday) 
                + "/" + ((now->tm_mon <= 8) ? "0" : "") + std::to_string(now->tm_mon + 1) 
                + " " + ((now->tm_hour <= 9) ? "0" : "") + std::to_string(now->tm_hour) 
                + ":" + ((now->tm_min <= 9) ? "0" : "") + std::to_string(now->tm_min);

        sqlite3_exec(db, 
                SEND_MSG_QUERY(last_msg_id, msg_datetime, author, req.content.substr(sizeof("user_message"))).c_str(), 
                nullptr, 
                0, 
                nullptr);

        sqlite3_close(db);

        return true;
    }

    Response::Response(const Request& req) : protocol(req.protocol), protocol_ver(req.protocol_ver), content_len("0")
    {
        if (req.method == NOT_SUPPORTED) {
            status = "501";
            reason = "Not Implemented";
            return;
        }

        if (req.method == GET) {
            std::ifstream infile;

            if (req.address == "/") {
                infile = std::ifstream("index.html");
            } else if (req.address == "/feed.html") {
                if (!check_access(req, "login.db")) {
                    return;
                }

                infile = std::ifstream("." + req.address);
            } else {
                infile = std::ifstream("." + req.address);
            }

            if (infile.fail()) {
                status = "404";
                reason = "Not Found";
                return;
            }

            content_type = define_MIME(req.address);

            std::string line;

            while (std::getline(infile, line)) {
                content += line + "\n";

                if (req.address == "/feed.html" && line.find("Last 10 messages:") != line.npos) {
                    std::unique_lock<std::mutex> lk(msg_db_mutex);

                    std::vector<std::string> messages;

                    sqlite3 *db;
                    sqlite3_open("messages.db", &db);

                    sqlite3_exec(db, "SELECT * FROM messages ORDER BY msgID DESC LIMIT 10;",
                            msg_callback_function, &messages, nullptr);
                    sqlite3_close(db);

                    content += "<br>";

                    std::reverse(messages.begin(), messages.end());

                    for (const auto& m : messages) {
                        content += m;
                    }
                }
            }

            content_len = std::to_string(content.size());
            status = "200";
            reason = "OK";

            return;
        } else if (req.method == POST) {
            if (req.address != "/feed.html") {
                status = "400";
                reason = "Bad Request\n";
                return;
            }

            std::ifstream infile;
            std::string login;

            if (!check_access(req, "login.db", &login)) {
                return;
            }

            infile = std::ifstream("." + req.address);

            if (!send_message(req, "messages.db", login)) {
                return;
            }

            status = "303";
            reason = "See other\nLocation: /feed.html";

            return;
        }

        status = "501";
        reason = "Not Implemented";
    }

    int 
    send_response(int sockfd, const Response& resp, int flags = 0)
    {
        std::string msg;
        msg += resp.protocol + "/" + resp.protocol_ver + " " + resp.status + " " + resp.reason + "\n";

        if (resp.status == "200") {
            msg += "Content-Type: " + resp.content_type + "\n";
        }

        msg += "Content-Length: " + resp.content_len + "\n\n";
        msg += resp.content + "\0";

        return send(sockfd, msg.c_str(), msg.size(), flags);
    }
}

int
server_setup(const char *ip, const char *port, addrinfo*& servinfo)
{
    int status;
    addrinfo hints;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((status = getaddrinfo(ip, port, &hints, &servinfo)) != 0) {
        std::cerr << "getaddrinfo error: " << gai_strerror(status) << std::endl;
        std::exit(EXIT_FAILURE);
    }

    int sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    
    if (int tmp = 1; setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp)) == -1) {
        std::cerr << "setsockopt error: " << std::strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }

    if (bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) == -1) {
        std::cerr << "bind error: " << std::strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }

    return sockfd;
}


int 
main(int argc, char **argv)
{
    addrinfo *servinfo;
    int sockfd = server_setup("127.0.0.1", "8000", servinfo);

    long long connections = 1;

    while (true) {
        if (listen(sockfd, BACKLOG) == -1) {
            std::cerr << "listen error: " << std::strerror(errno) << std::endl;
            std::exit(EXIT_FAILURE);
        }

        int new_fd = accept(sockfd, nullptr, nullptr);

        if (new_fd == -1) {
            std::cerr << "accept error: " << std::strerror(errno) << std::endl;
            std::exit(EXIT_FAILURE);
        }

        int pid = fork();

        if (pid == -1) {
            std::cerr << "fork error: " << std::strerror(errno) << std::endl;
            std::exit(EXIT_FAILURE);
        }

        if (!pid) {
            close(sockfd);
            const long long this_id(connections);
            std::cout << "Successfully connected; id = " << this_id << std::endl;

            while (true) {
                char req_str[RECV_BUF_SZ];
                recv(new_fd, &req_str, sizeof(req_str), 0);
                std::cout << req_str << std::endl;

                std::string in_req(req_str);
                http::Request req(in_req);

                http::Response resp(req);
                int bytes_sent = send_response(new_fd, resp);
            }

            freeaddrinfo(servinfo);
            close(new_fd);

            return 0;
        }

        close(new_fd);
        ++connections;
    }

    freeaddrinfo(servinfo);

    return 0;
}