#include "http.hpp"
#define WWWROOT "./wwwroot/"

std::string RequestStr(const HttpRequest &req)
{
    std::stringstream ss;
    ss << req._method << " " << req._path << " " << req._version << "\r\n";
    for (auto &it : req._params)
    {
        ss << it.first << ": " << it.second << "\r\n";
    }

    for (auto &it : req._headers)
    {
        ss << it.first << ": " << it.second << "\r\n";
    }

    ss << "\r\n";
    ss << req._body;
    return ss.str();
}

// 让该任务休眠 = 执行业务时长超过timeout
void Hello(const HttpRequest &req, HttpResponse *resp)
{
    resp->SetContent(RequestStr(req), "text/plain");
}

void Login(const HttpRequest &req, HttpResponse *resp)
{
    resp->SetContent(RequestStr(req), "text/plain");
}

void PutFile(const HttpRequest &req, HttpResponse *resp)
{
    std::string size = req.GetHeader("Content-Length");
    std::string pathname = WWWROOT + req._path;
    Util::WriteFile(pathname, req._body);
}

void DelFile(const HttpRequest &req, HttpResponse *resp)
{
    resp->SetContent(RequestStr(req), "text/plain");
}

int main()
{
    HttpServer server(8801);
    // 4线程
    server.SetThreadCount(3);
    // 设置静态资源根⽬录，告诉服务器有静态资源请求到来，需要到哪⾥去找资源⽂件
    server.SetBaseDir(WWWROOT);

    // 功能性方法
    server.Get("/hello", Hello);
    server.Post("/login", Login);
    server.Put("/1234.txt", PutFile);
    server.Delete("/1234.txt", DelFile);
    server.Listen();
    return 0;
}