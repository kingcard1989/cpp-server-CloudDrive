#pragma once
#include <string>
bool auth_ok(const std::string&authorization);
std::string auth_challenge();
bool base64_decode(const std::string& in,std::string&out);
bool auth_init(const std::string& config_path);
#include <map>
std::map<std::string, std::string> load_env(const std::string& path);
