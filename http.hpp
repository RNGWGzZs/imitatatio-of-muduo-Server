#pragma once
#include "Util.hpp"

#define ERROR_HTML "./error.html"
#define DEFAULT_VERSION "HTTP/1.1"
static int num = 0;
// HttpRequest请求类实现
class HttpRequest
{
public:
    std::string _method;  // 请求⽅法
    std::string _path;    // 资源路径
    std::string _version; // 协议版本
    std::string _body;    // 请求正⽂
    std::smatch _matches; // 资源路径的正则提取数据

    std::unordered_map<std::string, std::string> _headers; // 头部字段
    std::unordered_map<std::string, std::string> _params;  // 查询字符串
    HttpRequest() : _version(DEFAULT_VERSION) {}
    void ReSet()
    {
        // 资源清理
        _method.clear();
        _path.clear();
        _version = DEFAULT_VERSION;
        _body.clear();
        std::smatch match;
        _matches.swap(match);
        _headers.clear();
        _params.clear();
    }

    // 插⼊头部字段
    void SetHeader(const std::string &key, const std::string &val)
    {
        _headers.insert(std::make_pair(key, val));
    }

    // 判断是否存在指定头部字段
    bool HasHeader(const std::string &key) const
    {
        auto iter = _headers.find(key);
        if (iter == _headers.end())
        {
            return false;
        }
        return true;
    }

    // 获取指定头部字段的值
    std::string GetHeader(const std::string &key) const
    {
        auto it = _headers.find(key);
        if (it == _headers.end())
        {
            return "";
        }
        return it->second;
    }

    void SetParam(const std::string &key, const std::string &val)
    {
        _params.insert(std::make_pair(key, val));
    }

    // 判断是否有某个指定的查询字符串
    bool HasParam(const std::string &key) const
    {
        auto it = _params.find(key);
        if (it == _params.end())
        {
            return false;
        }
        return true;
    }

    // 获取指定的查询字符串
    std::string GetParam(const std::string &key) const
    {
        auto it = _params.find(key);
        if (it == _params.end())
        {
            return "";
        }
        return it->second;
    }

    // 获取正⽂⻓度
    size_t ContentLength() const
    {
        bool ret = HasHeader("Content-Length");
        if (ret == false)
        {
            return 0;
        }

        std::string clen = GetHeader("Content-Length");
        return std::stoi(clen);
    }

    // 判断是否是短链接
    bool Close() const
    {
        // 没有Connection字段，或者有Connection但是值是close，则都是短链接，否则就是⻓连接
        if (HasHeader("Connection") == true && GetHeader("Connection") == "keep-alive")
        {
            return false;
        }
        return true;
    }
};

class HttpResponse
{
public:
    int _status_code;          // 状态码
    bool _redirect_flag;       // 重定向标志
    std::string _redirect_url; // 重定向url
    std::string _body;         // 正文
    std::unordered_map<std::string, std::string> _headers;

    HttpResponse() : _redirect_flag(false), _status_code(200) {}
    HttpResponse(int status_code) : _redirect_flag(false), _status_code(status_code) {}
    void Reset()
    {
        _status_code = 200;
        _redirect_flag = false;
        _body.clear();
        _redirect_url.clear();
        _headers.clear();
    }

    // 插⼊头部字段
    void SetHeader(const std::string &key, const std::string &val)
    {
        _headers.insert(std::make_pair(key, val));
    }

    bool HasHeader(const std::string &key)
    {
        auto it = _headers.find(key);
        if (it == _headers.end())
        {
            return false;
        }
        return true;
    }

    // 获取指定头部字段的值
    std::string GetHeader(const std::string &key)
    {
        auto it = _headers.find(key);
        if (it == _headers.end())
        {
            return "";
        }
        return it->second;
    }

    void SetContent(const std::string &body, const std::string &type = "text/html")
    {
        _body = body;
        SetHeader("Content-Type", type);
    }

    void SetRedirect(const std::string &url, int status_code = 302)
    {
        _status_code = status_code;
        _redirect_flag = true;
        _redirect_url = url;
    }

    // 判断是否是短链接
    bool Close()
    {
        // 没有Connection字段，或者有Connection但是值是close，则都是短链接，否则就是⻓连接
        if (HasHeader("Connection") == true && GetHeader("Connection") == "keep-alive")
        {
            return false;
        }
        return true;
    }
};

// 五种接收状态
// 可能出现数据 但报文不完整的情况
typedef enum
{
    RECV_HTTP_ERROR,
    RECV_HTTP_LINE,
    RECV_HTTP_HEAD,
    RECV_HTTP_BODY,
    RECV_HTTP_OVER
} HttpRecvStatu;


#define MAX_LINE 1024
class HttpContext
{
private:
    int _status_code;           // 响应状态码
    HttpRecvStatu _recv_status; // 当前接收及解析的阶段状态
    HttpRequest _request;       // 已经解析得到的请求信息
private:
    // 解析请求行
    bool ParseHttpLine(const std::string &line)
    {
        std::smatch matches;
        std::regex reg("(GET|HEAD|POST|PUT|DELETE) ([^?]*)(?:\\?(.*))?(HTTP/1\\.[01])(?:\n|\r\n)?", std::regex::icase);
        bool ret = std::regex_match(line, matches, reg);

        if (ret == false)
        {
            _recv_status = RECV_HTTP_ERROR;
            _status_code = 400; // BAD REQUEST
            return false;
        }

        // 0 : GET /wwwroot/login?user=xiaoming&pass=123123 HTTP/1.1
        // 1 : GET      --->        请求方法
        // 2 : /wwwroot/login       --->    资源路径
        // 3 : user=xiaoming&pass=123123    ---> 提交参数params
        // 4 :  HTTP/1.1            --->    协议版本
        _request._method = matches[1];
        std::transform(_request._method.begin(), _request._method.end(), _request._method.begin(), ::toupper);

        // 资源路径的获取，需要进⾏URL解码操作，但是不需要+转空格
        _request._path = Util::UrlDecode(matches[2], false);
        _request._path.pop_back();

        // 协议版本的获取
        _request._version = matches[4];

        // 查询字符串的获取与处理
        //  3 : user=xiaoming&pass=123123    ---> 提交参数params
        std::vector<std::string> query_string_arry;
        std::string query_string = matches[3];
        Util::Split(query_string, "&", &query_string_arry);

        for (auto &str : query_string_arry)
        {
            size_t pos = str.find("=");
            // 协议切换
            if (pos == std::string::npos)
            {
                _recv_status = RECV_HTTP_ERROR;
                _status_code = 400; // BAD REQUEST
                return false;
            }
            std::string key = Util::UrlDecode(str.substr(0, pos), true);
            std::string val = Util::UrlDecode(str.substr(pos + 1), true);
            _request.SetParam(key, val);
        }
        return true;
    }

    // 解析头部字段
    bool ParseHttpHead(std::string &line)
    {
        // key: val\r\nkey: val\r\n....
        if (line.back() == '\n')
            line.pop_back(); // 末尾是换⾏则去掉换⾏字符
        if (line.back() == '\r')
            line.pop_back(); // 末尾是回⻋则去掉回⻋字符

        size_t pos = line.find(": ");
        if (pos == std::string::npos)
        {
            _recv_status = RECV_HTTP_ERROR;
            _status_code = 400;
            return false;
        }

        std::string key = line.substr(0, pos);
        std::string val = line.substr(pos + 2);
        _request.SetHeader(key, val);
        return true;
    }

public:
    // 获取请求行
    bool RecvHttpLine(Buffer *buf)
    {
        if (_recv_status != RECV_HTTP_LINE)
            return false;

        // 1. 获取⼀⾏数据，带有末尾的换⾏
        std::string line = buf->GetOneLine();
        // 需要考虑的⼀些要素：缓冲区中的数据不⾜⼀⾏， 获取的⼀⾏数据超⼤
        if (line.size() == 0)
        {
            // 缓冲区中的数据不⾜⼀⾏，则需要判断缓冲区的可读数据⻓度，如果很⻓了或者都不⾜⼀⾏，这是有问题
            if (buf->ReadAbleSize() > MAX_LINE)
            {
                _recv_status = RECV_HTTP_ERROR;
                _status_code = 414; // URI TOO LONG
                return false;
            }
            // 缓冲区中数据不⾜⼀⾏，但是也不多，就等等新数据的到来
            return true;
        }

        if (line.size() > MAX_LINE)
        {
            _recv_status = RECV_HTTP_ERROR;
            _status_code = 414; // URI TOO LONG
            return false;
        }

        // 解析请求行
        bool ret = ParseHttpLine(line);
        if (ret == false)
        {
            return false;
        }

        // ⾸⾏处理完毕，进⼊头部获取阶段
        _recv_status = RECV_HTTP_HEAD;
        return true;
    }

    // 获取头部字段
    bool RecvHttpHead(Buffer *buf)
    {
        if (_recv_status != RECV_HTTP_HEAD)
            return false;

        // ⼀⾏⼀⾏取出数据，直到遇到空⾏为⽌， 头部的格式 key: val\r\nkey:val\r\n....
        while (1)
        {
            // 需要考虑的⼀些要素：缓冲区中的数据不⾜⼀⾏， 获取的⼀⾏数据超⼤
            std::string line = buf->GetOneLine();
            if (line.size() == 0)
            {
                // 缓冲区中的数据不⾜⼀⾏，则需要判断缓冲区的可读数据⻓度，如果很⻓了都不⾜⼀⾏，这是有问题的
                if (buf->ReadAbleSize() > MAX_LINE)
                {
                    _recv_status = RECV_HTTP_ERROR;
                    _status_code = 414; // URI TOO LONG
                    return false;
                }
            }

            if (line.size() > MAX_LINE)
            {
                _recv_status = RECV_HTTP_ERROR;
                _status_code = 414; // URI TOO LONG
                return false;
            }

            if (line == "\n" || line == "\r\n")
            {
                break;
            }

            bool ret = ParseHttpHead(line);
            if (ret == false)
            {
                return false;
            }
        }

        // 头部处理完毕，进⼊正⽂获取阶段
        _recv_status = RECV_HTTP_BODY;
        return true;
    }

    bool RecvHttpBody(Buffer *buf)
    {
        if (_recv_status != RECV_HTTP_BODY)
            return false;

        // 获取正⽂⻓度
        size_t content_length = _request.ContentLength();
        if (content_length == 0)
        {
            // 没有正⽂，则请求接收解析完毕
            _recv_status = RECV_HTTP_OVER;
            return true;
        }

        // 当前已经接收了多少正⽂,其实就是往 _request._body 中放了多少数据了
        // 实际还需要接收的正⽂⻓度
        size_t real_len = content_length - _request._body.size();

        // 1.接收正⽂放到body中，但是也要考虑当前缓冲区中的数据，是否是全部的正⽂
        if (buf->ReadAbleSize() >= real_len)
        {
            // 缓冲区中数据，包含了当前请求的所有正⽂，则取出所需的数据
            _request._body.append(buf->ReadPosition(), real_len);
            buf->MoveReadOffset(real_len);
            _recv_status = RECV_HTTP_OVER;
            return true;
        }

        // 2.缓冲区中数据，⽆法满⾜当前正⽂的需要，数据不⾜，取出数据，然后等待新数据到来
        _request._body.append(buf->ReadPosition(), buf->ReadAbleSize());
        buf->MoveReadOffset(buf->ReadAbleSize());
        return true;
    }

public:
    HttpContext() : _status_code(200), _recv_status(RECV_HTTP_LINE) {}
    void ReSet()
    {
        _status_code = 200;
        _recv_status = RECV_HTTP_LINE;
        _request.ReSet();
    }

    int get_status_code() { return _status_code; }
    HttpRecvStatu get_recv_status() { return _recv_status; }
    HttpRequest &Request() { return _request; }
    // 接收并解析HTTP请求
    void RecvHttpRequest(Buffer *buf)
    {
        // 不同的状态，做不同的事情，但是这⾥不要break， 因为处理完请求⾏后，应该⽴即处理头部，⽽不是退出等新数据
        switch (_recv_status)
        {
        case RECV_HTTP_LINE:
            RecvHttpLine(buf);
        case RECV_HTTP_HEAD:
            RecvHttpHead(buf);
        case RECV_HTTP_BODY:
            RecvHttpBody(buf);
        }
        return;
    }
};

class HttpServer
{
private:
    using Handler = std::function<void(const HttpRequest &, HttpResponse *)>;
    // 功能性请求:请求方法 映射 对应方法
    // 这里不能使用 unordered_map容器,因为regex没有重载
    // operator比较
    using Handlers = std::vector<std::pair<std::regex, Handler>>;
    Handlers _get_route;
    Handlers _post_route;
    Handlers _put_route;
    Handlers _delete_route;

    std::string _base_dir;
    TcpServer _server;

private:
    // 访问静态资源
    bool IsFileHandler(const HttpRequest &req)
    {
        // 1. 必须设置了静态资源根⽬录
        if (_base_dir.empty())
        {
            return false;
        }

        // 2. 请求⽅法，必须是GET / HEAD请求⽅法
        if (req._method != "GET" && req._method != "HEAD")
        {
            return false;
        }

        // 3.请求的资源路径必须是⼀个合法路径
        if (Util::ValidPath(req._path) == false)
        {
            return false;
        }

        // 4.请求的资源必须存在,且是⼀个普通⽂件
        // 但如果访问的某个目录 那么这种情况下默认追加index.html
        // image/ --> image/index.html
        // 这是相对路径，绝对路径需要带上base目录 ./wwwroot/image/a.png
        // 为了避免直接修改请求的资源路径，因此定义⼀个临时对象
        std::string req_path = _base_dir + req._path;
        if (req._path.back() == '/')
        {
            // 访问目录
            req_path += "index.html";
        }

        if (Util::IsRegular(req_path) == false)
        {
            // 不是普通文件
            return false;
        }

        return true;
    }

    // 静态资源的请求处理 --- 将静态资源⽂件的数据读取出来，放到rsp的_body中, 并设置mime
    void FileHandler(const HttpRequest &req, HttpResponse *resp)
    {
        std::string req_path = _base_dir + req._path;
        if (req._path.back() == '/')
        {
            req_path += "index.html";
        }

        // 读取文件
        bool ret = Util::ReadFile(req_path, &resp->_body);
        if (ret == false)
        {
            return;
        }

        // 文件类型
        std::string mime = Util::ExtMime(req_path);
        resp->SetHeader("Content-Type", mime);
    }

private:
    // 错误处理
    void ErrorHandler(const HttpRequest &req, HttpResponse *resp)
    {
        // 返回错误页面
        std::string body;
        Util::ReadFile(ERROR_HTML, &body);
        resp->SetContent(body);
    }

    // 将HttpResponse中的要素按照http协议格式进⾏组织、发送
    void WriteReponse(const PtrConnection &conn, const HttpRequest &req, HttpResponse &resp)
    {
        // 1. 先完善头部字段
        if (req.Close() == true)
        {
            resp.SetHeader("Connection", "close");
        }
        else
        {
            resp.SetHeader("Connection", "keep-alive");
        }

        if (resp._body.empty() == false && resp.HasHeader("Content-Length") == false)
        {
            resp.SetHeader("Content-Length", std::to_string(resp._body.size()));
        }

        if (resp._redirect_flag == true)
        {
            resp.SetHeader("Location", resp._redirect_url);
        }

        // 将resp中的要素，按照http协议格式进⾏组织
        std::stringstream resp_line;
        resp_line << req._version << " " << std::to_string(resp._status_code) << " "
                  << Util::StatuDesc(resp._status_code) << "\r\n";

        // 组织头部字段
        for (auto &header : resp._headers)
        {
            resp_line << header.first << ": " << header.second << "\r\n";
        }

        // 空行
        resp_line << "\r\n";
        resp_line << resp._body;

        // 数据发送
        conn->Send(resp_line.str().c_str(), resp_line.str().size());
    }

    // 功能性请求的分类处理
    void Dispatcher(HttpRequest &req, HttpResponse *resp, Handlers &handlers)
    {
        // 在对应请求⽅法的路由表(handlers)中
        // 查找是否含有对应资源请求的处理函数，有则调⽤，没有则发送404
        for (auto &handler : handlers)
        {
            const std::regex &re = handler.first;
            const Handler &functor = handler.second;
            bool ret = std::regex_match(req._path, req._matches, re);
            if (ret == false)
            {
                continue;
            }
            return functor(req, resp); // 传⼊请求信息，和空的rsp，执⾏处理函数
        }

        DBG_LOG("404:%s", req._path.c_str());
        resp->_status_code = 404;
    }

    void Route(HttpRequest &req, HttpResponse *resp)
    {
        // 对请求进⾏分辨，是⼀个静态资源请求，还是⼀个功能性请求:
        // 1.静态资源请求，则进⾏静态资源的处理
        // 2.功能性请求，则需要通过⼏个请求路由表来确定是否有处理函数
        // 3.既不是静态资源请求，也没有设置对应的功能性请求处理函数，就返回405
        if (IsFileHandler(req) == true)
        {
            FileHandler(req, resp);
        }

        if (req._method == "GET" || req._method == "HEAD")
        {
            return Dispatcher(req, resp, _get_route);
        }
        else if (req._method == "POST")
        {
            return Dispatcher(req, resp, _post_route);
        }
        else if (req._method == "PUT")
        {
            return Dispatcher(req, resp, _put_route);
        }
        else if (req._method == "DELETE")
        {
            return Dispatcher(req, resp, _delete_route);
        }

        resp->_status_code = 405;
    }

public:
    // 设置上下⽂
    void OnConnected(const PtrConnection &conn)
    {
        conn->SetContext(HttpContext());
        DBG_LOG("NEW CONNECTION %p", conn.get());
    }

    // 缓冲区数据解析+处理
    void OnMessage(const PtrConnection &conn, Buffer *buffer)
    {
        while (buffer->ReadAbleSize() > 0)
        {
            // 1. 获取上下⽂
            HttpContext *context = conn->GetContext()->get<HttpContext>();
            // 通过上下⽂对缓冲区数据进⾏解析，得到HttpRequest对象
            // 1. 如果缓冲区的数据解析出错，就直接回复出错响应
            // 2. 如果解析正常，且请求已经获取完毕，才开始去进⾏处理
            context->RecvHttpRequest(buffer);
            HttpRequest &req = context->Request();
            HttpResponse resp(context->get_status_code());
            if (context->get_status_code() >= 400)
            {
                // 进⾏错误响应，并关闭连接
                //  填充⼀个错误显⽰⻚⾯数据到rsp中
                ErrorHandler(req, &resp);
                // 组织响应发送给客⼾端
                WriteReponse(conn, req, resp);
                context->ReSet();
                buffer->MoveReadOffset(buffer->ReadAbleSize()); // 出错了就把缓冲区数据清空
                conn->Shutdown();                               // 关闭连接
                return;
            }

            if (context->get_recv_status() != RECV_HTTP_OVER)
            {
                // 当前请求还没有接收完整,则退出，等新数据到来再重新继续处理
                return;
            }

            // 3. 请求路由 + 业务处理
            Route(req, &resp);

            // 4. 对HttpResponse进⾏组织发送
            WriteReponse(conn, req, resp);

            // 5. 重置上下⽂
            context->ReSet();

            // 6. 根据⻓短连接判断是否关闭连接或者继续处理
            if (resp.Close() == true)
            {
                conn->Shutdown(); // 短链接则直接关闭
            }
        }
        return;
    }

public:
    HttpServer(int port, int timeout = DEFALT_TIMEOUT) : _server(port)
    {
        _server.EnableInactiveRelease(timeout);
        _server.SetConnectedCallback(std::bind(&HttpServer::OnConnected, this, std::placeholders::_1));
        _server.SetMessageCallback(std::bind(&HttpServer::OnMessage, this, std::placeholders::_1, std::placeholders::_2));
    }

    void SetBaseDir(const std::string path)
    {
        assert(Util::IsDirectory(path) == true);
        _base_dir = path;
    }

    // 设置/添加，请求（请求的正则表达）与处理函数的映射关系
    void Get(const std::string &pattern, const Handler &handler)
    {
        _get_route.push_back(std::make_pair(std::regex(pattern), handler));
    }

    void Post(const std::string &pattern, const Handler &handler)
    {
        _post_route.push_back(std::make_pair(std::regex(pattern), handler));
    }

    void Put(const std::string &pattern, const Handler &handler)
    {
        _put_route.push_back(std::make_pair(std::regex(pattern), handler));
    }

    void Delete(const std::string &pattern, const Handler &handler)
    {
        _delete_route.push_back(std::make_pair(std::regex(pattern), handler));
    }

    void SetThreadCount(int count)
    {
        _server.SetThreadCount(count);
    }

    void Listen()
    {
        DBG_LOG("HttpServer Start...");
        _server.Start();
    }
};