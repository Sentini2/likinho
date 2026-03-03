#pragma once
#include <string>
#include <sstream>
#include <random>
#include <algorithm>
#include <regex>

namespace LuaObfuscator
{
    // Generate random variable name
    inline std::string RandomVarName()
    {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> dis(0x1000, 0xFFFF);
        
        std::stringstream ss;
        ss << "_0x" << std::hex << dis(gen);
        return ss.str();
    }

    // Encode string to string.char() format
    inline std::string EncodeString(const std::string& str)
    {
        if (str.empty()) return "\"\"";
        
        std::stringstream ss;
        ss << "string.char(";
        for (size_t i = 0; i < str.size(); i++)
        {
            ss << (int)(unsigned char)str[i];
            if (i < str.size() - 1) ss << ",";
        }
        ss << ")";
        return ss.str();
    }

    // Obfuscate all string literals in the script
    inline std::string ObfuscateStrings(const std::string& script)
    {
        std::string result = script;
        std::regex stringPattern(R"(\"([^\"]*)\")"); // Match "string"
        
        std::string temp;
        size_t lastPos = 0;
        std::smatch match;
        std::string searchStr = result;
        
        while (std::regex_search(searchStr, match, stringPattern))
        {
            temp += searchStr.substr(0, match.position());
            temp += EncodeString(match[1].str());
            
            lastPos = match.position() + match.length();
            searchStr = searchStr.substr(lastPos);
            lastPos = 0;
        }
        temp += searchStr;
        
        return temp;
    }

    // Add random junk code at the beginning
    inline std::string AddJunkCode()
    {
        std::stringstream ss;
        ss << "local " << RandomVarName() << "=" << (rand() % 1000) << "\n";
        ss << "local " << RandomVarName() << "=function()return " << (rand() % 100) << " end\n";
        return ss.str();
    }

    // Main obfuscation function
    inline std::string ObfuscateScript(const std::string& script)
    {
        if (script.empty()) return script;

        std::stringstream result;
        
        // Add junk code header
        result << AddJunkCode();
        
        // Obfuscate strings
        std::string obfuscated = ObfuscateStrings(script);
        
        // Add obfuscated script
        result << obfuscated;
        
        // Add junk code footer
        result << "\n" << AddJunkCode();
        
        return result.str();
    }
}
