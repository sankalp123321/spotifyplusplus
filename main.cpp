#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include <future>
#include <iostream>
#include <string>
#include <map>
#include <csignal>
#include "Auth/auth.hpp"

#define CA_CERT_FILE "./ca-bundle.crt"

volatile std::sig_atomic_t gSignalStatus = 0;

std::string dump_headers(const httplib::Headers &headers)
{
  std::string s;
  char buf[BUFSIZ];

  for (auto it = headers.begin(); it != headers.end(); ++it)
  {
    const auto &x = *it;
    snprintf(buf, sizeof(buf), "%s: %s\n", x.first.c_str(), x.second.c_str());
    s += buf;
  }

  return s;
}

void logger(const httplib::Request &req, const httplib::Response &res)
{
  std::string s;
  char buf[BUFSIZ];

  s += "================================\n";

  snprintf(buf, sizeof(buf), "%s %s %s", req.method.c_str(),
           req.version.c_str(), req.path.c_str());
  s += buf;

  std::string query;
  for (auto it = req.params.begin(); it != req.params.end(); ++it)
  {
    const auto &x = *it;
    snprintf(buf, sizeof(buf), "%c%s=%s",
             (it == req.params.begin()) ? '?' : '&', x.first.c_str(),
             x.second.c_str());
    query += buf;
  }
  snprintf(buf, sizeof(buf), "%s\n", query.c_str());
  s += buf;

  s += dump_headers(req.headers);

  s += req.body;
 
  s += "--------------------------------\n";

  snprintf(buf, sizeof(buf), "%d %s\n", res.status, res.version.c_str());
  s += buf;
  s += dump_headers(res.headers);
  s += "\n";

  if (!res.body.empty())
  {
    s += res.body;
  }

  s += "\n";

  std::cout << s;
}


std::map<std::string, std::string> mappify2(std::string const& s)
{
    std::map<std::string, std::string> m;

    std::string::size_type key_pos = 0;
    std::string::size_type key_end;
    std::string::size_type val_pos;
    std::string::size_type val_end;

    while((key_end = s.find(':', key_pos)) != std::string::npos)
    {
        if((val_pos = s.find_first_not_of(": ", key_end)) == std::string::npos)
            break;

        if((val_end = s.find('\n', val_pos)) == std::string::npos)
            val_end = s.size();

        m.emplace(s.substr(key_pos, key_end - key_pos), s.substr(val_pos, val_end - val_pos));

        key_pos = val_end + 1;

        if(val_end == s.size())
            break;
    }

    return m;
}

int main(int argc, char *argv[])
{
  std::string access_token = "";
  std::string token_type = "";
  std::string expires_in = "";
  std::string refresh_token = "";

  auth oauth;
  std::string codeVerifString = "tTbT66TqR5Vd7QWnJvHUwKdOd-oZz9rfODwE9BuM4~nvO9VVocpWkDlA~LXxE~OTC8X97CHxBsfPm0kMMKhxNEvKNC7QBFjB~4-64Bo4sFDQ3maBw7y79fDHi9XhA4h_";
  // std::string codeVerifString = oauth.AuthCodeVerifier(128);
  auto sha256CodedString = oauth.sha256Encode(codeVerifString);
#if 0
  for(uint16_t idx = 0; idx < 32; idx++)
  {
    printf("%d 0x%X\n", sha256CodedString[idx], sha256CodedString[idx]);
  }
#endif
  // oauth.AuthCodeChallenge();
  auto codeChallengeString = oauth.AuthCodeChallenge(sha256CodedString, 32);

  // std::string inputString = codeChallengeString;
  printf("code Challenge [%s]\n", codeChallengeString.c_str());

#if 1
  httplib::Server http;
  http.set_logger(logger);

  httplib::Client sendPage{"localhost", 8081};
  httplib::SSLClient bot("accounts.spotify.com");
  bot.set_ca_cert_path(CA_CERT_FILE);
  bot.enable_server_certificate_verification(false);
  bot.set_keep_alive(false);
  bot.set_follow_location(true);
  bot.set_logger(logger);

  httplib::Headers headers = {
      {"client_id", "1dddfe60d8c347baa4614e5e93a53e8f"},
      {"response_type", "code"},
      {"redirect_uri", "http://localhost:8888/callback"},
      {"scope", "user-read-private user-read-email user-modify-playback-state"},
      {"code_challenge_method", "S256"},
      {"code_challenge", codeChallengeString.c_str()},
      {"show_dialog", "true"}};

  std::string auth_url = bot.host() + "/authorize?";

  auto it = headers.begin();
  for (; it != headers.end(); it++)
  {
    auth_url += it->first + "=" + it->second + "&";
  }

  std::cout << "Browse to url: " << auth_url << std::endl;

  // httplib::Server& (httplib::Server::*gf)(const std::string &pattern, httplib::Server::Handler handler) = &httplib::Server::Get;
  std::string retVal = "";
  auto a1 = std::thread([&]()
  { 
      std::string message = "Go back to your terminal :)";
      
      http.Get("/callback", [&](const httplib::Request &req, httplib::Response &res) {
        res.set_content(message, "text/plain");
        // code = req.get_param_value("code");
        retVal = req.get_param_value("code");

        httplib::Params authTokenHeader = {
          // {"Content-Type", "application/x-www-form-urlencoded"},
          {"grant_type", "authorization_code"},
          {"code", retVal},
          {"redirect_uri", "http://localhost:8888/callback"},
          {"client_id", "1dddfe60d8c347baa4614e5e93a53e8f"},
          {"code_verifier", codeVerifString}
        };

        std::string op = httplib::detail::params_to_query_str(authTokenHeader);

        if (auto res = bot.Post("/api/token", op, "application/x-www-form-urlencoded")) {
            printf("Result Code[%d]\n", res->status);
            if (res->status == httplib::StatusCode::OK_200) {
              std::string inp = res->body;
              inp.erase(std::remove(inp.begin(), inp.end(), '"'), inp.end());
              inp.erase(std::remove(inp.begin(), inp.end(), '{'), inp.end());
              inp.erase(std::remove(inp.begin(), inp.end(), '}'), inp.end());
              
              for(auto itr = inp.begin(); itr != inp.end(); itr++)
              {
                  if(*itr == ',')
                  {
                      *itr = '\n';
                  }
              }
              
              auto keyValuePair = mappify2(inp);
            
              access_token = keyValuePair["access_token"];
              token_type = keyValuePair["token_type"];
              expires_in = keyValuePair["expires_in"];
              refresh_token = keyValuePair["refresh_token"];

              printf("access_token[%s]\ntoken_type[%s]\nexpires_in[%s]\nrefresh_token[%s]\n",\
                access_token.c_str(), token_type.c_str(), expires_in.c_str(), refresh_token.c_str());
              

              gSignalStatus = 1;
              
            }
        } else {
            auto err = res.error();
            std::cout << "HTTP error: " << httplib::to_string(err) << std::endl;
            auto result = bot.get_openssl_verify_result();
            if (result) 
            {
                std::cout << "verify error: " << X509_verify_cert_error_string(result) << std::endl;
            }
        }

      });
      
      http.listen("localhost", 8888);
      return; 
  });


  while(!gSignalStatus)
  {
    sleep(1);
  }

  httplib::SSLClient api("api.spotify.com");
  api.set_ca_cert_path(CA_CERT_FILE);
  api.enable_server_certificate_verification(false);
  api.set_keep_alive(false);
  api.set_follow_location(true);
  api.set_logger(logger);
  
  // std::string putBody = "Authorization: Bearer "+access_token;
  httplib::Headers pauseHeader = {
    {"Authorization", "Bearer "+access_token},
    // {"device_id","0d1841b0976bae2a3a310dd74c0f3df354899bc8"},
  };
  // std::string heaaderPause = httplib::detail::params_to_query_str(pauseHeader);
  if (auto res = api.Put("/v1/me/player/pause", pauseHeader, nullptr, 0, "application/x-www-form-urlencoded")) {
    printf("Result Code[%d]\n", res->status);
    if (res->status == httplib::StatusCode::OK_200) {
    }
  }

  // http.listen("localhost", 8888);

  printf("Code[%s]\n", retVal.c_str());

#if 0
    httplib::Headers authTokenHeader = {
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"grant_type", "authorization_code"},
        {"code", retVal},
        {"redirect_uri", "http://localhost:8888/callback"},
        {"client_id", "1dddfe60d8c347baa4614e5e93a53e8f"},
        {"code_verifier", codeVerifString}
    };
    if (auto res = bot.Post("/api/token", authTokenHeader)) {
      printf("Result Code[%d]\n", res->status);
        if (res->status == httplib::StatusCode::OK_200) {

        }
    } else {
        auto err = res.error();
        std::cout << "HTTP error: " << httplib::to_string(err) << std::endl;
        auto result = bot.get_openssl_verify_result();
        if (result) 
        {
            std::cout << "verify error: " << X509_verify_cert_error_string(result) << std::endl;
        }
    }
#endif
#if USING_MANUAL_AUTH
  if (auto res = bot.Get("/authorize", headers))
  {
    printf("Result Code[%d]\n", res->status);
    if (res->status == httplib::StatusCode::OK_200)
    {
    }
  }
  else
  {
    auto err = res.error();
    std::cout << "HTTP error: " << httplib::to_string(err) << std::endl;
    auto result = bot.get_openssl_verify_result();
    if (result)
    {
      std::cout << "verify error: " << X509_verify_cert_error_string(result) << std::endl;
    }
  }
#endif
  a1.join();
#else
  using namespace std;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  // httplib::SSLClient cli("localhost", 8080);
  httplib::SSLClient cli("accounts.spotify.com");
  // httplib::SSLClient cli("www.youtube.com");
  cli.set_ca_cert_path(CA_CERT_FILE);
  cli.enable_server_certificate_verification(true);
#else
  httplib::Client cli("localhost", 8080);
#endif

  if (auto res = cli.Get("/hi"))
  {
    cout << res->status << endl;
    cout << res->get_header_value("Content-Type") << endl;
    cout << res->body << endl;
  }
  else
  {
    cout << "error code: " << res.error() << std::endl;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    auto result = cli.get_openssl_verify_result();
    if (result)
    {
      cout << "verify error: " << X509_verify_cert_error_string(result) << endl;
    }
#endif
  }

#endif
  return 0;
}