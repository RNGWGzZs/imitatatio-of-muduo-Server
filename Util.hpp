#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>
#include <sys/stat.h>
#include "../server.hpp"
#define DEFALT_TIMEOUT 20

static std::unordered_map<int, std::string> _statu_msg = {
    {100, "Continue"},
    {101, "Switching Protocol"},
    {102, "Processing"},
    {103, "Early Hints"},
    {200, "OK"},
    {201, "Created"},
    {202, "Accepted"},
    {203, "Non-Authoritative Information"},
    {204, "No Content"},
    {205, "Reset Content"},
    {206, "Partial Content"},
    {207, "Multi-Status"},
    {208, "Already Reported"},
    {226, "IM Used"},
    {300, "Multiple Choice"},
    {301, "Moved Permanently"},
    {302, "Found"},
    {303, "See Other"},
    {304, "Not Modified"},
    {305, "Use Proxy"},
    {306, "unused"},
    {307, "Temporary Redirect"},
    {308, "Permanent Redirect"},
    {400, "Bad Request"},
    {401, "Unauthorized"},
    {402, "Payment Required"},
    {403, "Forbidden"},
    {404, "Not Found"},
    {405, "Method Not Allowed"},
    {406, "Not Acceptable"},
    {407, "Proxy Authentication Required"},
    {408, "Request Timeout"},
    {409, "Conflict"},
    {410, "Gone"},
    {411, "Length Required"},
    {412, "Precondition Failed"},
    {413, "Payload Too Large"},
    {414, "URI Too Long"},
    {415, "Unsupported Media Type"},
    {416, "Range Not Satisfiable"},
    {417, "Expectation Failed"},
    {418, "I'm a teapot"},
    {421, "Misdirected Request"},
    {422, "Unprocessable Entity"},
    {423, "Locked"},
    {424, "Failed Dependency"},
    {425, "Too Early"},
    {426, "Upgrade Required"},
    {428, "Precondition Required"},
    {429, "Too Many Requests"},
    {431, "Request Header Fields Too Large"},
    {451, "Unavailable For Legal Reasons"},
    {501, "Not Implemented"},
    {502, "Bad Gateway"},
    {503, "Service Unavailable"},
    {504, "Gateway Timeout"},
    {505, "HTTP Version Not Supported"},
    {506, "Variant Also Negotiates"},
    {507, "Insufficient Storage"},
    {508, "Loop Detected"},
    {510, "Not Extended"},
    {511, "Network Authentication Required"}};

static std::unordered_map<std::string, std::string> _mime_msg =
    {
        {".aac", "audio/aac"},
        {".abw", "application/x-abiword"},
        {".arc", "application/x-freearc"},
        {".avi", "video/x-msvideo"},
        {".azw", "application/vnd.amazon.ebook"},
        {".bin", "application/octet-stream"},
        {".bmp", "image/bmp"},
        {".bz", "application/x-bzip"},
        {".bz2", "application/x-bzip2"},
        {".csh", "application/x-csh"},
        {".css", "text/css"},
        {".csv", "text/csv"},
        {".doc", "application/msword"},
        {".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        {".eot", "application/vnd.ms-fontobject"},
        {".epub", "application/epub+zip"},
        {".gif", "image/gif"},
        {".htm", "text/html"},
        {".html", "text/html"},
        {".ico", "image/vnd.microsoft.icon"},
        {".ics", "text/calendar"},
        {".jar", "application/java-archive"},
        {".jpeg", "image/jpeg"},
        {".jpg", "image/jpeg"},
        {".js", "text/javascript"},
        {".json", "application/json"},
        {".jsonld", "application/ld+json"},
        {".mid", "audio/midi"},
        {".midi", "audio/x-midi"},
        {".mjs", "text/javascript"},
        {".mp3", "audio/mpeg"},
        {".mpeg", "video/mpeg"},
        {".mpkg", "application/vnd.apple.installer+xml"},
        {".odp", "application/vnd.oasis.opendocument.presentation"},
        {".ods", "application/vnd.oasis.opendocument.spreadsheet"},
        {".odt", "application/vnd.oasis.opendocument.text"},
        {".oga", "audio/ogg"},
        {".ogv", "video/ogg"},
        {".ogx", "application/ogg"},
        {".otf", "font/otf"},
        {".png", "image/png"},
        {".pdf", "application/pdf"},
        {".ppt", "application/vnd.ms-powerpoint"},
        {".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
        {".rar", "application/x-rar-compressed"},
        {".rtf", "application/rtf"},
        {".sh", "application/x-sh"},
        {".svg", "image/svg+xml"},
        {".swf", "application/x-shockwave-flash"},
        {".tar", "application/x-tar"},
        {".tif", "image/tiff"},
        {".tiff", "image/tiff"},
        {".ttf", "font/ttf"},
        {".txt", "text/plain"},
        {".vsd", "application/vnd.visio"},
        {".wav", "audio/wav"},
        {".weba", "audio/webm"},
        {".webm", "video/webm"},
        {".webp", "image/webp"},
        {".woff", "font/woff"},
        {".woff2", "font/woff2"},
        {".xhtml", "application/xhtml+xml"},
        {".xls", "application/vnd.ms-excel"},
        {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
        {".xml", "application/xml"},
        {".xul", "application/vnd.mozilla.xul+xml"},
        {".zip", "application/zip"},
        {".3gp", "video/3gpp"},
        {".3g2", "video/3gpp2"},
        {".7z", "application/x-7z-compressed"},
};

class Util
{
public:
    // 1.字符串分割函数
    static int Split(const std::string &src, const std::string sep, std::vector<std::string> *arr)
    {
        // 上一次sep位置
        size_t offset = 0;
        while (offset < src.size())
        {
            size_t pos = src.find(sep, offset);
            if (pos == std::string::npos)
            {
                // 将剩余的部分当作⼀个字串，放⼊arry中
                if (pos == src.size())
                    break;
                arr->push_back(src.substr(offset));
                return arr->size();
            }

            // 出现连续sep的情况
            // "a++cbed"
            if (pos == offset)
            {
                offset = pos + sep.size();
                continue;
            }
            arr->push_back(src.substr(offset, pos - offset));
            offset = pos + sep.size();
        }
        return arr->size();
    }

    static bool ReadFile(const std::string &filename, std::string *buf)
    {
        std::ifstream ifs(filename, std::ios::binary);
        if (ifs.is_open() == false)
        {
            std::cout << "open file: " << filename.c_str() << " "
                      << "faild..." << std::endl;
            return false;
        }

        size_t fsize = 0;
        // 跳转读写位置到末尾
        ifs.seekg(0, ifs.end);
        // 获取当前读写位置相对于起始位置的偏移量
        fsize = ifs.tellg();
        ifs.seekg(0, ifs.beg);

        buf->resize(fsize);
        ifs.read(&(*buf)[0], fsize);

        if (ifs.good() == false)
        {
            std::cout << "read file:" << filename.c_str() << "faild..." << std::endl;
            ifs.close();
            return false;
        }

        ifs.close();
        return false;
    }

    // 向⽂件写⼊数据
    static bool WriteFile(const std::string &filename, const std::string &buf)
    {
        std::ofstream ofs(filename, std::ios::binary | std::ios::trunc);
        if (ofs.is_open() == false)
        {
            std::cout << "open file:" << filename.c_str() << "faild..." << std::endl;
            return false;
        }

        ofs.write(buf.c_str(), buf.size());
        std::cout << buf.size() << std::endl;
        if (ofs.good() == false)
        {
            std::cout << "write file:" << filename.c_str() << "faild..." << std::endl;
            ofs.close();
            return false;
        }

        ofs.close();
        return true;
    }

    // 响应状态码的描述信息获取
    static std::string StatuDesc(int statu)
    {
        auto it = _statu_msg.find(statu);
        if (it != _statu_msg.end())
        {
            return it->second;
        }

        return "Unknow";
    }

    // 根据⽂件后缀名获取⽂件mime
    static std::string ExtMime(const std::string &filename)
    {
        // a.b.txt 先获取⽂件扩展名
        size_t pos = filename.find_last_of('.');
        if (pos == std::string::npos)
        {
            return "application/octet-stream";
        }

        std::string ext = filename.substr(pos);
        auto it = _mime_msg.find(ext);
        if (it == _mime_msg.end())
        {
            // 默认返回二进制流
            return "application/octet-stream";
        }
        return it->second;
    }

    // 判断⼀个⽂件是否是⼀个⽬录
    static bool IsDirectory(const std::string &filename)
    {
        struct stat st;
        int ret = stat(filename.c_str(), &st);
        if (ret < 0)
        {
            return false;
        }

        return S_ISDIR(st.st_mode);
    }

    // 判断⼀个⽂件是否是⼀个普通⽂件
    static bool IsRegular(const std::string &filename)
    {
        struct stat st;
        int ret = stat(filename.c_str(), &st);
        if (ret < 0)
        {
            return false;
        }
        return S_ISREG(st.st_mode);
    }

    static bool ValidPath(const std::string &path)
    {
        std::vector<std::string> subdir;
        Split(path, "/", &subdir);
        int level = 0; // 当前层为0
        for (auto &dir : subdir)
        {
            // 访问上级目录
            if (dir == "..")
            {
                level--;
                if (level < 0)
                    return false;
                continue;
            }
            level++;
        }
        return true;
    }

    // URL编码，避免URL中资源路径与查询字符串中的特殊字符与HTTP请求中特殊字符产⽣歧义
    static std::string UrlEncode(const std::string url, bool convert_space_to_plus)
    {
        std::string res;
        for (auto &ch : url)
        {
            if (ch == '.' || ch == '_' || ch == '-' || ch == '~' || isalnum(ch))
            {
                // 绝不进行编码的字符
                res += ch;
                continue;
            }

            // w3c转换
            if (ch == ' ' && convert_space_to_plus == true)
            {
                res += '+';
                continue;
            }

            // 需要进行编码字符
            // 格式为: %HH
            char tmp[4] = {0};
            // 格式化字符
            // %: %%
            // 十六进制: %X
            // 02:两个字符 左边补0
            snprintf(tmp, sizeof(tmp), "%%%02X", ch);
            res += tmp;
        }
        return res;
    }

    static char HEXTOI(char c)
    {
        if (c >= '0' && c <= '9')
        {
            return c - '0';
        }
        else if (c >= 'a' && c <= 'z')
        {
            return c - 'a' + 10;
        }
        else if (c >= 'A' && c <= 'Z')
        {
            return c - 'A' + 10;
        }
        return -1;
    }

    static std::string UrlDecode(const std::string url, bool convert_plus_to_space)
    {
        // 遇到了%，则将紧随其后的2个字符，转换为数字
        //  数字: 16进制 --> 10进制
        //  '+':43(D) 2B(H)
        //  2*16 + B*1: 32+11 = 43
        //  让第一个数 左移4位 + 第二个数
        std::string res;
        for (int i = 0; i < url.size(); ++i)
        {
            if (url[i] == '+' && convert_plus_to_space == true)
            {
                res += ' ';
                continue;
            }

            // 需要解码
            if (url[i] == '%' && (i + 2) < url.size())
            {
                char v1 = HEXTOI(url[i + 1]);
                char v2 = HEXTOI(url[i + 2]);
                char tmp = v1 * 16 + v2;

                res += tmp;
                i += 2;
                continue; // 这里的continue是跳转到判断位置 而不会进行++
            }
            // 普通字符
            res += url[i];
        }
        return res;
    }
};