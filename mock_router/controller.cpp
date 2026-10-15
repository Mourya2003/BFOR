#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <map>
#include <unordered_map>
#include <mutex>
#include <random>
#include <iomanip>
#include <cctype>

#include <boost/asio.hpp>
#include <boost/beast.hpp>

using namespace std;

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;

using tcp = asio::ip::tcp;

// Stores active session tokens and their usernames.
unordered_map<string, string> sessions;
mutex sessionsMutex;

// Read a file into a string.
string readFile(const string& path) {
    ifstream file(path, ios::binary);

    if (!file) {
        return "";
    }

    ostringstream contents;
    contents << file.rdbuf();

    return contents.str();
}

// Convert a hexadecimal character into its numeric value.
int hexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;

    return -1;
}

// Decode URL-encoded form data.
string urlDecode(const string& input) {
    string output;

    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '+') {
            output += ' ';
        } else if (input[i] == '%' && i + 2 < input.size()) {
            int high = hexValue(input[i + 1]);
            int low = hexValue(input[i + 2]);

            if (high != -1 && low != -1) {
                output += static_cast<char>(high * 16 + low);
                i += 2;
            } else {
                output += input[i];
            }
        } else {
            output += input[i];
        }
    }

    return output;
}

// Parse data such as username=admin&password=admin123.
map<string, string> parseForm(const string& body) {
    map<string, string> fields;
    size_t start = 0;

    while (start < body.size()) {
        size_t end = body.find('&', start);

        if (end == string::npos) {
            end = body.size();
        }

        string item = body.substr(start, end - start);
        size_t equals = item.find('=');

        if (equals != string::npos) {
            string key = urlDecode(item.substr(0, equals));
            string value = urlDecode(item.substr(equals + 1));

            fields[key] = value;
        }

        start = end + 1;
    }

    return fields;
}

// Check credentials against the vault file.
bool authenticate(const string& username, const string& password) {
    ifstream file("vault/users.txt");

    if (!file) {
        throw runtime_error("Could not open vault/users.txt");
    }

    string line;

    while (getline(file, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        size_t separator = line.find(':');

        if (separator == string::npos) {
            continue;
        }

        string savedUsername = line.substr(0, separator);
        string savedPassword = line.substr(separator + 1);

        if (savedUsername == username &&
            savedPassword == password) {
            return true;
        }
    }

    return false;
}

// Generate a random token for a login session.
string generateSessionToken() {
    random_device random;
    ostringstream token;

    for (int i = 0; i < 4; ++i) {
        token << hex << setw(8) << setfill('0')
              << static_cast<unsigned int>(random());
    }

    return token.str();
}

// Escape user-controlled text before inserting it into HTML.
string escapeHtml(const string& input) {
    string output;

    for (char c : input) {
        switch (c) {
            case '&':  output += "&amp;";  break;
            case '<':  output += "&lt;";   break;
            case '>':  output += "&gt;";   break;
            case '"':  output += "&quot;"; break;
            case '\'': output += "&#39;";  break;
            default:   output += c;        break;
        }
    }

    return output;
}

// Read the session cookie and find its username.
string getSessionUsername(const http::request<http::string_body>& request) {
    string cookies(request[http::field::cookie]);
    const string prefix = "session=";

    size_t start = 0;

    while (start < cookies.size()) {
        size_t end = cookies.find(';', start);

        if (end == string::npos) {
            end = cookies.size();
        }

        string item = cookies.substr(start, end - start);

        while (!item.empty() &&
               isspace(static_cast<unsigned char>(item.front()))) {
            item.erase(item.begin());
        }

        if (item.compare(0, prefix.size(), prefix) == 0) {
            string token = item.substr(prefix.size());

            lock_guard<mutex> lock(sessionsMutex);
            auto it = sessions.find(token);

            if (it != sessions.end()) {
                return it->second;
            }

            return "";
        }

        start = end + 1;
    }

    return "";
}

void handleClient(tcp::socket socket) {
    try {
        beast::flat_buffer buffer;
        http::request<http::string_body> request;

        http::read(socket, buffer, request);

        string target(request.target());
        size_t queryPosition = target.find('?');

        if (queryPosition != string::npos) {
            target = target.substr(0, queryPosition);
        }

        http::response<http::string_body> response{
            http::status::ok, request.version()
        };

        response.keep_alive(false);
        response.set(http::field::server, "MyCppServer");

        // GET /
        if (request.method() == http::verb::get &&
            target == "/") {

            response.set(
                http::field::content_type,
                "text/html; charset=utf-8"
            );

            response.body() =
                "<!DOCTYPE html><html><body>"
                "<h1>Welcome to my server!</h1>"
                "<a href=\"/login\">Go to login</a>"
                "</body></html>";
        }

        // GET /login
        else if (request.method() == http::verb::get &&
                 target == "/login") {

            string page = readFile("webpages/login.html");

            if (page.empty()) {
                response.result(http::status::internal_server_error);
                response.body() = "Could not read login.html";
                response.set(
                    http::field::content_type,
                    "text/plain; charset=utf-8"
                );
            } else {
                response.set(
                    http::field::content_type,
                    "text/html; charset=utf-8"
                );
                response.body() = page;
            }
        }

        // GET /login.js
        else if (request.method() == http::verb::get &&
                 target == "/login.js") {

            string script = readFile("webpages/login.js");

            if (script.empty()) {
                response.result(http::status::internal_server_error);
                response.body() = "Could not read login.js";
                response.set(
                    http::field::content_type,
                    "text/plain; charset=utf-8"
                );
            } else {
                response.set(
                    http::field::content_type,
                    "application/javascript; charset=utf-8"
                );
                response.body() = script;
            }
        }

        // POST /login
        else if (request.method() == http::verb::post &&
                 target == "/login") {

            map<string, string> fields = parseForm(request.body());

            string username = fields["username"];
            string password = fields["password"];

            if (username.empty() || password.empty()) {
                response.result(http::status::bad_request);
                response.body() =
                    R"({"success":false,"message":"Enter your username and password."})";
                response.set(
                    http::field::content_type,
                    "application/json; charset=utf-8"
                );
            } else {
                try {
                    if (authenticate(username, password)) {
                        string token = generateSessionToken();

                        {
                            lock_guard<mutex> lock(sessionsMutex);
                            sessions[token] = username;
                        }

                        response.set(
                            http::field::set_cookie,
                            "session=" + token +
                            "; Path=/; HttpOnly; SameSite=Lax"
                        );

                        response.body() =
                            R"({"success":true})";
                    } else {
                        response.result(http::status::unauthorized);

                        response.body() =
                            R"({"success":false,"message":"Wrong username or password."})";
                    }

                    response.set(
                        http::field::content_type,
                        "application/json; charset=utf-8"
                    );
                } catch (const exception& e) {
                    cerr << "Authentication error: "
                         << e.what() << '\n';

                    response.result(
                        http::status::internal_server_error
                    );

                    response.set(
                        http::field::content_type,
                        "application/json; charset=utf-8"
                    );

                    response.body() =
                        R"({"success":false,"message":"Server error. Please try again later."})";
                }
            }
        }

        // GET /dashboard
        else if (request.method() == http::verb::get &&
                 target == "/dashboard") {

            string username = getSessionUsername(request);

            if (username.empty()) {
                response.result(http::status::unauthorized);
                response.set(
                    http::field::content_type,
                    "text/html; charset=utf-8"
                );

                response.body() =
                    "<!DOCTYPE html><html><body>"
                    "<h2>Please log in first.</h2>"
                    "<a href=\"/login\">Go to login</a>"
                    "</body></html>";
            } else {
                string page = readFile("webpages/dashboard.html");

                if (page.empty()) {
                    response.result(
                        http::status::internal_server_error
                    );
                    response.body() = "Could not read dashboard.html";
                    response.set(
                        http::field::content_type,
                        "text/plain; charset=utf-8"
                    );
                } else {
                    const string placeholder = "{{USERNAME}}";
                    const string safeUsername = escapeHtml(username);

                    size_t position = 0;

                    while ((position = page.find(
                                placeholder, position)) != string::npos) {
                        page.replace(
                            position,
                            placeholder.size(),
                            safeUsername
                        );

                        position += safeUsername.size();
                    }

                    response.set(
                        http::field::content_type,
                        "text/html; charset=utf-8"
                    );

                    response.body() = page;
                }
            }
        }

        // Unsupported HTTP methods.
        else if (request.method() != http::verb::get &&
                 request.method() != http::verb::post) {

            response.result(http::status::method_not_allowed);
            response.body() = "Method not allowed";

            response.set(
                http::field::content_type,
                "text/plain; charset=utf-8"
            );
        }

        // Unknown routes.
        else {
            response.result(http::status::not_found);
            response.body() = "404 - Not found";

            response.set(
                http::field::content_type,
                "text/plain; charset=utf-8"
            );
        }

        response.prepare_payload();
        http::write(socket, response);

        beast::error_code error;
        socket.shutdown(tcp::socket::shutdown_send, error);

    } catch (const exception& e) {
        cerr << "Client error: " << e.what() << '\n';
    }
}

int main(int argc, char* argv[]) {
    try {
        unsigned short port = 8080;

        if (argc > 1) {
            int requestedPort = stoi(argv[1]);

            if (requestedPort < 1 || requestedPort > 65535) {
                cerr << "Port must be between 1 and 65535.\n";
                return 1;
            }

            port = static_cast<unsigned short>(requestedPort);
        }

        asio::io_context io;

        tcp::acceptor acceptor(
            io,
            tcp::endpoint(tcp::v4(), port)
        );

        cout << "Server running at http://localhost:"
             << port << '\n';

        while (true) {
            tcp::socket socket(io);
            acceptor.accept(socket);

            thread(
                handleClient,
                move(socket)
            ).detach();
        }

    } catch (const exception& e) {
        cerr << "Server error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}