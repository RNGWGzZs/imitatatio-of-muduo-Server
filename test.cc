#include "http.hpp"

using namespace std;

int main()
{
    std::string str = "/login";
    std::regex reg("/login");
    std::smatch sm;

    bool ret = std::regex_match(str,sm,reg);
    if(ret == false)
    {
        cerr << "解析失败" << endl;
        return -1;
    }
    
    cout << sm[0] << endl;
    return 0;
}

// int main()
// {
//     // bool ret = Util::IsDirectory(WWWROOT);
//     // if (ret == false)
//     // {
//     //     cout << "不是是一个目录" << endl;
//     //     return -1;
//     // }
//     // cout << "是一个目录" << endl;

//     // std::string url = "www.baidu.com/wd=c++";
//     // std::string res = Util::UrlEncode(url, false);
//     // std::cout << "编码后:" << res << std::endl;
//     // res = Util::UrlDecode(url, false);
//     // std::cout << "解码后:" << res << std::endl;

//     // std::string url2 = "www.baidu.com/wd=c++";
//     // res = Util::UrlEncode(url, true);
//     // std::cout << "w3c编码后:" << res << std::endl;
//     // res = Util::UrlDecode(url, false);
//     // std::cout << "w3c解码后:" << res << std::endl;

//     // string body = "Say its a new World!";
//     // string filename = "index.html";
//     // Util::WriteFile(filename, body);

//     // std::vector<std::string> params;
//     // std::string sep = ",";
//     // std::string str = "abc,def,ghj,,,ed,";
//     // int size = Util::Split(str,sep,&params);

//     // for(auto & str : params)
//     // {
//     //     std::cout << "[" << str << "]" << std::endl;
//     // }
//     return 0;
// }