#include <iostream>
#include <cstdlib>
#include <cstring>
#include <queue>
#include <cerrno>
#include <fstream>
#include <map>
#include <sstream>

#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <chrono>

#include <sqlite3.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

enum
{
    BACKLOG = 10,

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
    WEBP
};

struct DB_request;

std::mutex db_lock;
std::condition_variable cv;
static std::atomic<long long> pid_reading{0}; 
std::queue<DB_request> db_req_queue;
std::string db_response;


struct DB_request
{
    std::string db_name;
    std::string table_name;
    std::string op;
    int pid;

    DB_request(std::string&& db_str, std::string&& table_str, std::string&& op_str, int connection_id) :
            db_name(db_str), table_name(table_str), op(op_str), pid(connection_id) {};
};

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

    Request::Request(std::string& req_str) 
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

        // ss >> tmp >> host;
        // ss >> tmp;
        ss.get();
        ss.get();
        // std::getline(ss, user_agent);

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

        Response(const Request& req, const long long& this_id);

        std::string 
        define_MIME(const std::string& address) const
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
    };

    Response::Response(const Request& req, const long long& this_id) : protocol(req.protocol), protocol_ver(req.protocol_ver)
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
            } else if (req.address == "/kitty.html") {
                std::cout << req.user_key << std::endl;

                if (req.user_key.size() == 0) {
                    status = "401";
                    reason = "Unauthorized\nWWW-Authenticate: Basic realm=\"Wally World\"\n\n";
                    return;
                } else {
                    db_lock.lock();
                    std::cout << "WOW!\n" << std::endl;
                    db_req_queue.push(DB_request("login.db", "auth_users", "SELECT DISTINCT * FROM auth_users WHERE user_key = " + req.user_key + ";", this_id));
                    db_lock.unlock();

                    std::mutex tmp_m;
                    std::unique_lock tmp_lk(tmp_m);

                    while (pid_reading != this_id) {
                        cv.wait(tmp_lk);

                        if (pid_reading != this_id) continue;
                    }

                    std::string cur_db_resp = db_response;
                    std::cout << "GOT DB RESPONSE:\n\n" + cur_db_resp + "\n\n\n\n=======================\n" << std::endl;
                    pid_reading.store(0);
                    cv.notify_all();

                    status = "200";
                    reason = "OK";
                    return;
                }
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
            }

            content_len = std::to_string(content.size());
            status = "200";
            reason = "OK";

            return;
        } else if (req.method == POST) {

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
            msg += "Content-Length: " + resp.content_len + "\n\n";
            msg += resp.content + "\0";
        }

        return send(sockfd, msg.c_str(), msg.size(), flags);
    }
}

void db_thread_function()
{
    while (true) {
        // std::cout << "Waiting..." << std::endl;
        db_lock.lock();

        if (db_req_queue.size() == 0) {
            db_lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        while (db_req_queue.size() > 0) {
            std::cout << "Got in..." << std::endl;
            DB_request cur_req = db_req_queue.front();
            db_req_queue.pop();

            std::string db_response = std::to_string(cur_req.pid) + ":  " + cur_req.op;

            pid_reading.store(cur_req.pid);
            cv.notify_all();

            std::mutex m;
            std::unique_lock<std::mutex> lk(m);

            while (pid_reading) {
                cv.wait(lk);

                if (pid_reading) continue;
            }
        }

        db_lock.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

int 
main(int argc, char **argv)
{
    int status;
    addrinfo hints, *servinfo;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((status = getaddrinfo("127.0.0.1", "8000", &hints, &servinfo)) != 0) {
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


    std::thread db_query_handler(db_thread_function);
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


        int pid;

        if ((pid = fork()) == -1) {
            std::cerr << "fork error: " << std::strerror(errno) << std::endl;
            std::exit(EXIT_FAILURE);
        }

        if (!pid) {
            close(sockfd);
            const long long this_id(connections);
            std::cout << "Successfully connected; id = " << this_id << std::endl;

            while (true) {
                char req_str[20480], b;
                recv(new_fd, &req_str, sizeof(req_str), 0);
                // std::cout << req_str << std::endl;
                std::string in_req(req_str);

                http::Request req(in_req);

                if (req.method == GET) {
                    // std::cout << "Got GET\n";
                } else if (req.method == POST) {
                    // std::cout << "Got POST\n";
                    std::cout << req.content_type << "\n" << req.content_len << "\n" << req.content << std::endl;
                }


                http::Response resp(req, this_id);
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