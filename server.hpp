#pragma once
#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#include <unordered_map>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>

#include <cstring>
#include <ctime>
#include <cassert>
#include <cerrno>

#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>

#define INF 0
#define DBG 1
#define ERR 2
#define DEFAULT_LOG_LEVEL INF
#define LOG(level, format, ...)                                                             \
    do                                                                                      \
    {                                                                                       \
        if (level < DEFAULT_LOG_LEVEL)                                                      \
            break;                                                                          \
        time_t times = time(nullptr);                                                       \
        struct tm *t = localtime(&times);                                                   \
        char ts[32] = {0};                                                                  \
        strftime(ts, sizeof(ts), "%H:%M:%S", t);                                            \
        fprintf(stdout, "[%s:%d] [%s]" format "\n", __FILE__, __LINE__, ts, ##__VA_ARGS__); \
    } while (0)

#define INF_LOG(format, ...) LOG(INF, format, ##__VA_ARGS__)
#define DBG_LOG(format, ...) LOG(DBG, format, ##__VA_ARGS__)
#define ERR_LOG(format, ...) LOG(ERR, format, ##__VA_ARGS__)

// 实现⽤⼾态缓冲区，提供数据缓冲
const int buffer_default_size = 1024;
class Buffer
{
private:
    // 选用vector而不选用string 是考虑到 传输的数据含0字符的情况
    std::vector<char> _buffer;
    // 记录buffer内数据读取和写入位置
    uint64_t _reader_idx; // 读偏移
    uint64_t _writer_idx; // 写偏移

    // 管理读写位置
public:
    Buffer() : _reader_idx(0), _writer_idx(0), _buffer(buffer_default_size) {}
    char *Begin() { return &*(_buffer.begin()); }
    // 获取当前写⼊起始地址
    char *WritePosition() { return Begin() + _writer_idx; }
    // 获取当前读取起始地址
    char *ReadPosition() { return Begin() + _reader_idx; }

    // 获取缓冲区末尾空闲空间⼤⼩
    uint64_t TailIdleSize() { return _buffer.size() - _writer_idx; }
    // 获取缓冲区起始空闲空间⼤⼩ --> 这是获取可覆盖空间
    uint64_t HeadIdleSize() { return _reader_idx; }
    // 获取可读数据⼤⼩ = 写偏移 - 读偏移
    uint64_t ReadAbleSize() { return _writer_idx - _reader_idx; }

    // 将 读偏移 向后移动
    void MoveReadOffset(uint64_t len)
    {
        if (len == 0)
            return;
        // 读偏移向后移动 len不能超过可读数据大小
        assert(len <= ReadAbleSize());
        _reader_idx += len;
    }

    // 将写偏移向后移动
    void MoveWriteOffset(uint64_t len)
    {
        if (len == 0)
            return;
        // 写偏移向后移动 len必须⼩于当前后边的空闲空间⼤⼩
        assert(len <= TailIdleSize());
        _writer_idx += len;
    }

    // 管理读取、写入
public:
    void EnsureWriteSpace(uint64_t len)
    {
        // 可写空间的总大小为: TailIdleSize() + HeadIdleSize()
        // 1.如果末尾如果够插入 直接返回
        if (len <= TailIdleSize())
            return;
        // 2.如果不超过 "可写空间的总大小" 把原有数据向前挪动
        if (len <= TailIdleSize() + HeadIdleSize())
        {
            // 原先数据大小
            uint64_t res = ReadAbleSize();
            // 向前拷贝，合并空间
            std::copy(ReadPosition(), ReadPosition() + res, Begin());
            // 更新偏移量
            _reader_idx = 0;
            _writer_idx = res;
        }
        else
        {
            // 3.总体空间不够，则需要扩容，不移动数据，直接给写偏移之后扩容⾜够空间即可
            _buffer.resize(_writer_idx + len);
        }
    }

    // 真正的写入数据
    void Write(const void *data, size_t len)
    {
        // 1.保证空间足够
        if (len == 0)
            return;
        EnsureWriteSpace(len);

        // 2.数据拷贝
        const char *d = (const char *)data;
        std::copy(d, d + len, WritePosition());
    }

    // 写入数据 -> string类型
    void WriteString(const std::string &data)
    {
        WriteAndPush(data.c_str(), data.size());
    }

    // 写入数据 -> buffer类型
    void WriteBuffer(Buffer &buf)
    {
        WriteAndPush(buf.ReadPosition(), buf.ReadAbleSize());
    }

    // 写入数据+移动偏移量 ——> 最好使用这个
    void WriteAndPush(const void *data, size_t len)
    {
        Write(data, len);
        MoveWriteOffset(len);
    }

    // 真正的取出数据
    void Read(void *data, size_t len)
    {
        if (len == 0)
            return;
        // 要获取的数据⼤⼩必须⼩于可读数据⼤⼩
        assert(len <= ReadAbleSize());
        std::copy(ReadPosition(), ReadPosition() + len, (char *)data);
    }

    // 按照字符串方式取出 数据
    std::string ReadAsString(size_t len)
    {
        if (len == 0)
            return "";

        assert(len <= ReadAbleSize());
        std::string str;
        str.resize(len);

        ReadAndPop(&str[0], len);
        return str;
    }

    // 取出数据+移动偏移量 ——> 最好使用这个
    void ReadAndPop(void *data, size_t len)
    {
        Read(data, len);
        MoveReadOffset(len);
    }

    // 清空缓冲区
    void Clear()
    {
        _reader_idx = 0;
        _writer_idx = 0;
    }

    // HTTP处理
    char *FindCRLF()
    {
        char *res = (char *)memchr(ReadPosition(), '\n', ReadAbleSize());
        return res;
    }

    // 通常用于获取一行数据
    std::string GetOneLine()
    {
        char *pos = FindCRLF();
        if (pos == nullptr)
            return "";

        // 这里的+1 是将"\n"一并取出来
        return ReadAsString(pos - ReadPosition() + 1);
    }
};

// 为避免服务器向已经关闭的文件描述符输入
// OS会发送SIGPIPE信号终止程序
// 大多数服务器都会选择将这个信号忽略掉
class NetWork
{
public:
    NetWork()
    {
        INF_LOG("SIGPIPIE INIT");
        signal(SIGPIPE, SIG_IGN);
    }
};
// 定义静态全局是为了保证构造函数中的信号忽略处理能够在程序启动阶段就被直接执⾏
static NetWork nw;

#define MAX_LISTEN 1024
class Socket
{
private:
    int _sockfd;

public:
    Socket() : _sockfd(-1) {}
    Socket(int fd) : _sockfd(fd) {}
    ~Socket() { Close(); }
    int get_fd() { return _sockfd; }

    void Close()
    {
        if (_sockfd > 0)
        {
            close(_sockfd);
            _sockfd = -1;
        }
    }
    // 套接字创建
private:
    bool Create()
    {
        _sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (_sockfd < 0)
        {
            ERR_LOG("create socket faild...");
            return false;
        }
        return true;
    }

    bool Bind(const std::string &ip, uint16_t port)
    {
        struct sockaddr_in local;
        local.sin_family = AF_INET;
        local.sin_port = htons(port);
        local.sin_addr.s_addr = INADDR_ANY;

        if (bind(_sockfd, (const sockaddr *)&local, sizeof(local)) < 0)
        {
            ERR_LOG("bind socket faild...");
            return false;
        }
        return true;
    }

    bool Listen(int backlog = MAX_LISTEN)
    {
        if (listen(_sockfd, backlog) < 0)
        {
            ERR_LOG("listen socket faild...");
            return false;
        }
        return true;
    }

    void ReuseAddr()
    {
        int flag = 1;
        setsockopt(_sockfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
        int val = 1;
        setsockopt(_sockfd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
    }

    // 获取连接、建立连接
public:
    bool Connect(const std::string &ip, uint16_t port)
    {
        struct sockaddr_in peer;
        peer.sin_family = AF_INET;
        peer.sin_port = htons(port);
        peer.sin_addr.s_addr = inet_addr(ip.c_str());
        int ret = connect(_sockfd, (const sockaddr *)&peer, sizeof(peer));
        if (ret < 0)
        {
            ERR_LOG("connect socket faild...");
            return false;
        }
        return true;
    }

    int Accept()
    {
        // 这里不关心 发起连接一方的信息
        int newfd = accept(_sockfd, nullptr, nullptr);
        if (newfd < 0)
        {
            ERR_LOG("accept socket faild...");
            return -1;
        }
        return newfd;
    }

    void NonBlock()
    {
        // 获取_sockfd模式
        int flag = fcntl(_sockfd, F_GETFL, 0);
        // 设置非阻塞
        fcntl(_sockfd, F_SETFL, flag | O_NONBLOCK);
    }

    // 套接字的读和写 --> 真正的读写操作
    // buffer --> 只提供策略
public:
    ssize_t Recv(void *buf, size_t len, int flag = 0)
    {
        ssize_t s = recv(_sockfd, buf, len, flag);
        if (s < 0)
        {
            // 1.没有出错 只是缓冲区没数据或者被信号中断
            if (errno == EAGAIN || errno == EINTR)
            {
                // 表⽰这次接收没有接收到数据
                return 0;
            }
            // 2.真的出错了
            ERR_LOG("socket recv faild...");
            return -1;
        }
        // 实际接收的数据⻓度
        return s;
    }

    size_t Recv_NonBlock(void *buf, size_t len)
    {
        int size = Recv(buf, len, MSG_DONTWAIT);
        return size;
    }

    int Send(const void *buf, size_t len, int flag = 0)
    {
        ssize_t ret = send(_sockfd, buf, len, flag);
        if (ret < 0)
        {
            if (errno == EAGAIN || errno == EINTR)
            {
                return 0;
            }
            ERR_LOG("socket send faild...");
            return -1;
        }
        return ret;
    }

    ssize_t Send_NonBlock(const void *buf, size_t len)
    {
        return Send(buf, len, MSG_DONTWAIT);
    }

    // 构建服务端\客户端
public:
    bool CreateServer(uint16_t port, const std::string &ip = "0.0.0.0", bool block_flag = false)
    {
        if (Create() == false)
            return false;
        if (block_flag)
            NonBlock();
        if (Bind(ip, port) == false)
            return false;
        if (Listen() == false)
            return false;

        ReuseAddr();
        return true;
    }

    bool CreateClient(uint16_t port, const std::string &ip)
    {
        if (Create() == false)
            return false;
        if (Connect(ip, port) == false)
            return false;

        return true;
    }
};

// 每一个socket都对应一个 Channel
// 该Channel关心这个描述符上的设置的事件
// 当事件就绪时 就会调用被设置进的 回调函数
class Poller;
class EventLoop;
class Channel
{
private:
    int _fd;
    uint32_t _events;  // 该事件需要关心的 事件
    uint32_t _revents; // 就绪事件
    // One thread One Loop
    // 当一个线程 去处理一个开启监控的描述符上的事件
    // 它不是通过Channel子模块，而是通过EventLoop这个整合 事件监控、管理、修改等等的大模块
    // 找到对应描述符上关心的Channel事件，这里设置_loop是一种会指机制
    // 该Channel事件的处理 是放在这一个Loop这个thread之中的！
    EventLoop *_loop;

    using EventCallback = std::function<void()>;
    EventCallback _read_callback;  // 可读事件被触发的回调函数
    EventCallback _write_callback; // 可写事件被触发的回调函数
    EventCallback _error_callback; // 错误事件被触发的回调函数
    EventCallback _close_callback; // 连接断开事件被触发的回调函数
    EventCallback _event_callback; // 任意事件被触发的回调函数
public:
    // 回调函数设置
    void SetReadCallback(const EventCallback &cb) { _read_callback = cb; }
    void SetWriteCallback(const EventCallback &cb) { _write_callback = cb; }
    void SetErrorCallback(const EventCallback &cb) { _error_callback = cb; }
    void SetCloseCallback(const EventCallback &cb) { _close_callback = cb; }
    void SetEventCallback(const EventCallback &cb) { _event_callback = cb; }

public:
    Channel(EventLoop *loop, int fd) : _fd(fd), _events(0), _revents(0), _loop(loop)
    {
    }

    int get_fd() { return _fd; }
    // 获取想要监控的事件
    uint32_t get_events() { return _events; }
    // 设置实际就绪的事件
    void set_revents(uint32_t events) { _revents = events; }

    // 事件监控
    bool ReadAble() { return _events & EPOLLIN; }
    bool WriteAble() { return _events & EPOLLOUT; }

    // 启动\关闭读写事件
    // 这里的update和 Poller(修改事件监控)相关， 但我们可以通过回指loop指针 调用Poller里的内容
    void EnableRead()
    {
        _events |= EPOLLIN;
        Update();
    }

    void EnableWrite()
    {
        _events |= EPOLLOUT;
        Update();
    }

    void DisableRead()
    {
        _events &= ~EPOLLIN;
        Update();
    }
    void DisableWrite()
    {
        _events &= ~EPOLLOUT;
        Update();
    }
    void DisableAll()
    {
        _events = 0;
        Update();
    }

    void Update();
    void Remove();

public:
    // 事件处理，⼀旦连接触发了事件，就调⽤这个函数，⾃⼰触发了什么事件如何处理⾃⼰决定
    void HandlerEvent()
    {
        // 这些都与 读事件相关
        if ((_revents & EPOLLIN) || (_revents & EPOLLRDHUP) || (_revents & EPOLLPRI))
        {
            if (_read_callback)
                _read_callback();
        }

        /*有可能会释放连接的操作事件，⼀次只处理⼀个*/
        if (_revents & EPOLLOUT)
        {
            if (_write_callback)
                _write_callback();
        }
        else if (_revents & EPOLLERR)
        {
            if (_error_callback)
                _error_callback();
        }
        else if (_revents & EPOLLHUP)
        {
            if (_close_callback)
                _close_callback();
        }

        if (_event_callback)
            _event_callback();
    }
};

#define MAX_EPOLL_EVENTS 1024
class Poller
{
private:
    int _epfd;
    struct epoll_event _evs[MAX_EPOLL_EVENTS]; // 通过就绪队列 获取的就绪事件信息
    // [描述符,Channel]
    // 记录有多少描述符的Channel需要被管控
    std::unordered_map<int, Channel *> _channels;

private:
    // 真正修改监控
    // 增删改
    void Update(Channel *channel, int op)
    {
        int fd = channel->get_fd();
        struct epoll_event ev;
        ev.data.fd = fd;
        ev.events = channel->get_events();
        int ret = epoll_ctl(_epfd, op, fd, &ev);
        if (ret < 0)
        {
            ERR_LOG("epoll ctl error:%s\n", strerror(errno));
        }

        return;
    }

    bool HasChannel(Channel *channel)
    {
        auto iter = _channels.find(channel->get_fd());
        if (iter == _channels.end())
            return false;

        return true;
    }

public:
    Poller()
    {
        _epfd = epoll_create(MAX_EPOLL_EVENTS);
        if (_epfd < 0)
        {
            ERR_LOG("epoll create error:%s\n", strerror(errno));
            abort();
        }
    }

    void UpdateEvent(Channel *channel)
    {
        bool ret = HasChannel(channel);
        if (ret == false)
        {
            // 不存在 就添加
            _channels.insert(std::make_pair(channel->get_fd(), channel));
            return Update(channel, EPOLL_CTL_ADD);
        }

        return Update(channel, EPOLL_CTL_MOD);
    }

    void RemoveEvent(Channel *channel)
    {
        auto iter = _channels.find(channel->get_fd());
        if (iter != _channels.end())
        {
            _channels.erase(iter);
        }

        return Update(channel, EPOLL_CTL_DEL);
    }

    // 输出型参数，带出就绪事件的Channel
    void Epoll(std::vector<Channel *> *active)
    {
        // -1: 阻塞等待
        int nfds = epoll_wait(_epfd, _evs, MAX_EPOLL_EVENTS, -1);
        if (nfds < 0)
        {
            if (errno == EINTR)
            {
                return;
            }
            ERR_LOG("epoll wait error:%s\n", strerror(errno));
            abort();
        }

        // 事件就绪
        for (int i = 0; i < nfds; ++i)
        {
            auto iter = _channels.find(_evs[i].data.fd);
            assert(iter != _channels.end());

            iter->second->set_revents(_evs[i].events); // 设置事件就绪
            active->push_back(iter->second);           // 插入就绪事件数组
        }
        return;
    }
};

// 定时任务/清理资源函数
using TaskFunc = std::function<void()>;
using ReleaseFunc = std::function<void()>;
class TimerTask
{
private:
    int _timerfd;            // 定时器对象id
    uint32_t _timeout;       // 定时任务超时时间
    bool _canceled;          // 定时任务是否被取消
    TaskFunc _task_cb;       // 定时器对象要执⾏的定时任务
    ReleaseFunc _release_cb; // ⽤于删除TimerWheel中保存的定时器对象信息
public:
    TimerTask(int timerfd, uint32_t timeout, const TaskFunc &cb) : _timerfd(timerfd), _timeout(timeout),
                                                                   _task_cb(cb), _canceled(false) {}
    ~TimerTask()
    {
        if (_canceled == false)
            _task_cb();
        _release_cb();
    }
    void SetReleaseCallback(const ReleaseFunc &cb) { _release_cb = cb; }
    void Cancel() { _canceled = true; }
    uint32_t get_timeout() { return _timeout; }
};

class TimerWheel
{
private:
    using WeakTask = std::weak_ptr<TimerTask>;
    using PtrTask = std::shared_ptr<TimerTask>;

    int _tick;                                      // 当前的秒针，⾛到哪⾥释放哪⾥，释放哪⾥，执行该任务
    int _capacity;                                  // 表盘容量
    std::vector<std::vector<PtrTask>> _TimerWheels; // 表盘
    std::unordered_map<uint64_t, WeakTask> _timers; // 已经存在TimerTask
    EventLoop *_loop;

    // 定时任务通过Channel进行读监控
    // Channel _timer_channel;
    // 定时器描述符--可读事件回调就是读取计数器，执⾏定时任务
    int _timerfd;
    std::unique_ptr<Channel> _timer_channel;

private:
    void RemoveTimer(uint64_t id)
    {
        // 清理weak_ptr的 对象
        auto it = _timers.find(id);
        if (it != _timers.end())
        {
            _timers.erase(it);
        }
    }

    int CreateTimerfd()
    {
        int timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
        if (timerfd < 0)
        {
            ERR_LOG("TIMERFD CREATE FAILED!");
            abort();
        }

        struct itimerspec spec;
        spec.it_value.tv_sec = 1;
        spec.it_value.tv_nsec = 0;
        spec.it_interval.tv_sec = 1;
        spec.it_interval.tv_nsec = 0;
        timerfd_settime(timerfd, 0, &spec, nullptr);
        return timerfd;
    }

    // 每次超时会向_fd写入数据 触发读事件
    // 回调Ontime 处理tick指针
    int ReadTImerfd()
    {
        // 每秒向_timer写入
        int times;
        int ret = read(_timerfd, &times, 8);
        if (ret < 0)
        {
            ERR_LOG("READ TIMEFD FAILED!");
            abort();
        }

        return times;
    }

    void RunTimerTick()
    {
        _tick = (_tick + 1) % _capacity;
        // 这里清空数组内容 保存在里面的对象 会自动调用析构函数 -> 回调设置的超时任务
        _TimerWheels[_tick].clear();
    }

    void OnTime()
    {
        // 根据实际超时的次数，执⾏对应的超时任务
        int times = ReadTImerfd();
        // 每读取一次 就移动_tick
        for (int i = 0; i < times; ++i)
        {
            RunTimerTick();
        }
    }

    void TimerAddInLoop(uint64_t id, int delay, const TaskFunc &cb)
    {
        PtrTask ptr(new TimerTask(id, delay, cb));
        // 这里就设置 Release的callback
        ptr->SetReleaseCallback(std::bind(&TimerWheel::RemoveTimer, this, id));

        int pos = (_tick + delay) % _capacity;
        _TimerWheels[pos].push_back(ptr);
        _timers[id] = WeakTask(ptr);
    }

    void TimerRefreshInLoop(uint64_t id)
    {
        auto iter = _timers.find(id);
        if (iter == _timers.end())
        {
            return;
        }

        // lock 获取weakptr中的shared_ptr
        PtrTask ptr = iter->second.lock();
        // 重新计算位置插入
        int delay = ptr->get_timeout();
        int pos = (_tick + delay) % _capacity;
        _TimerWheels[pos].push_back(ptr);
    }

    void TimerCancelInLoop(uint64_t id)
    {
        auto iter = _timers.find(id);
        assert(iter != _timers.end());
        PtrTask ptr = iter->second.lock();
        if (ptr)
            ptr->Cancel();
    }

public:
    TimerWheel(EventLoop *loop) : _tick(0), _capacity(60), _TimerWheels(_capacity), _loop(loop),
                                  _timerfd(CreateTimerfd()), _timer_channel(new Channel(_loop, _timerfd))
    {
        // 设置读事件回调
        _timer_channel->SetReadCallback(std::bind(&TimerWheel::OnTime, this));
        _timer_channel->EnableRead();
    }

    // 定时任务(添加\刷新\取消)
    void TimerAdd(uint64_t id, uint32_t delay, const TaskFunc &cb);
    void TimerRefresh(uint64_t id);
    void TimerCancel(uint64_t id);

    bool HasTimer(uint64_t id)
    {
        auto iter = _timers.find(id);
        if (iter == _timers.end())
            return false;
        return true;
    }
};

// 可以是任意回调函数!
// 被压入进EventLoop进行处理
class EventLoop
{
private:
    using Functor = std::function<void()>;
    // one thread one loop
    std::thread::id _thread_id;
    // 唤醒IO事件监控有可能导致的阻塞
    int _event_fd;
    std::unique_ptr<Channel> _event_channel;
    Poller _poller;

    std::vector<Functor> _tasks; // 任务池
    std::mutex _mtx;             // 任务池线程安全
    TimerWheel _timer_wheel;     // 定时器模块
private:
    static int CreateEventFd()
    {
        int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (efd < 0)
        {
            ERR_LOG("CREATE EVENTFD FAILED!!");
            abort(); // 让程序异常退出
        }
        return efd;
    }

    // 执行任务池里的所有任务
    void RunAllTask()
    {
        std::vector<Functor> functor;
        {
            std::unique_lock<std::mutex> _lock(_mtx);
            _tasks.swap(functor);
        }
        for (auto &f : functor)
        {
            f();
        }
        return;
    }

    // 设置eventfd唤醒的 回调函数
    // 触发读事件
    void ReadEventfd()
    {
        uint64_t res = 0;
        int ret = read(_event_fd, &res, sizeof(res));
        if (ret < 0)
        {
            // EINTR -- 被信号打断； EAGAIN -- 表⽰⽆数据可读
            if (errno == EINTR || errno == EAGAIN)
            {
                return;
            }
            ERR_LOG("READ EVENTFD FAILED!");
            abort();
        }
        return;
    }

    void WeakUpEventFd()
    {
        uint64_t val = 1;
        int ret = write(_event_fd, &val, sizeof(val));
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                return;
            }
            ERR_LOG("READ EVENTFD FAILED!");
            abort();
        }
        return;
    }

public:
    EventLoop() : _thread_id(std::this_thread::get_id()), _event_fd(CreateEventFd()),
                  _event_channel(new Channel(this, _event_fd)),
                  _timer_wheel(this)
    {
        // 给eventfd添加可读事件回调函数，读取eventfd事件通知次数
        _event_channel->SetReadCallback(std::bind(&EventLoop::ReadEventfd, this));
        _event_channel->EnableRead();
    }

    void Start()
    {
        // 循环运行:
        // 1.事件监控 2.事件处理 3.执行任务
        while (1)
        {
            std::vector<Channel *> actives;
            _poller.Epoll(&actives); // 监控wait

            for (auto &channel : actives)
            {
                // 执行回调 处理事件就绪
                channel->HandlerEvent();
            }
            // 执行任务池里的任务
            RunAllTask();
        }
    }

    // 判断将要执⾏的任务是否处于当前线程中，如果是则执⾏，不是则压⼊队列
    void RunInLoop(const Functor &cb)
    {
        if (IsInLoop())
        {
            return cb();
        }
        return QueueInLoop(cb);
    }

    void QueueInLoop(const Functor &cb)
    {
        {
            std::unique_lock<std::mutex> _lock(_mtx);
            _tasks.push_back(cb);
        }
        // 唤醒有可能因为没有事件就绪，⽽导致的epoll阻塞；
        // 其实就是给eventfd写⼊⼀个数据，eventfd就会触发可读事件
        WeakUpEventFd();
    }

    // ⽤于判断当前线程是否是EventLoop对应的线程
    bool IsInLoop() { return _thread_id == std::this_thread::get_id(); }
    void AssertInLoop() { assert(_thread_id == std::this_thread::get_id()); }

    // 控制描述符
    void UpdateEvent(Channel *channel) { return _poller.UpdateEvent(channel); }
    void RemoveEvent(Channel *channel) { return _poller.RemoveEvent(channel); }

    // 管理超时任务
    void TimerAdd(uint64_t id, uint32_t delay, const TaskFunc &cb) { return _timer_wheel.TimerAdd(id, delay, cb); }
    void TimerRefresh(uint64_t id) { return _timer_wheel.TimerRefresh(id); }
    void TimerCancel(uint64_t id) { return _timer_wheel.TimerCancel(id); }
    bool HasTimer(uint64_t id) { return _timer_wheel.HasTimer(id); }
};

// Channel才保存着 监控哪些事件的信息，因此参数传this
void Channel::Remove() { return _loop->RemoveEvent(this); }
void Channel::Update() { return _loop->UpdateEvent(this); }

// 定时器中有个_timers成员，定时器信息的操作有可能在多线程中进⾏，因此需要考虑线程安全问题
// 如果不想加锁  One thread one loop 都放到⼀个线程中进⾏
void TimerWheel::TimerAdd(uint64_t id, uint32_t delay, const TaskFunc &cb)
{
    _loop->RunInLoop(std::bind(&TimerWheel::TimerAddInLoop, this, id, delay, cb));
}
void TimerWheel::TimerRefresh(uint64_t id)
{
    _loop->RunInLoop(std::bind(&TimerWheel::TimerRefreshInLoop, this, id));
}
void TimerWheel::TimerCancel(uint64_t id)
{
    _loop->RunInLoop(std::bind(&TimerWheel::TimerCancelInLoop, this, id));
}

// 避免线程创建了，但是_loop还没有实例化
class LoopThread
{
private:
    std::mutex _mtx;
    std::condition_variable _cond;
    // EventLoop指针变量，这个对象需要在线程内实例化
    // 线程对应的_loop
    EventLoop *_loop;
    // EventLoop对应的线程
    std::thread _thread;

private:
    void ThreadEntry()
    {
        EventLoop loop;
        {
            std::unique_lock<std::mutex> lock(_mtx); // 加锁
            _loop = &loop;
            _cond.notify_all();
        }
        loop.Start();
    }

public:
    LoopThread() : _loop(NULL), _thread(std::thread(&LoopThread::ThreadEntry, this)) {}
    EventLoop *GetLoop()
    {
        EventLoop *loop = NULL;
        {
            std::unique_lock<std::mutex> lock(_mtx); // 加锁
            _cond.wait(lock, [&]()
                       { return _loop != NULL; }); // loop为NULL就⼀直阻塞
            loop = _loop;
        }
        return loop;
    }
};

class LoopThreadPool
{
private:
    int _thread_count;
    int _next_idx; // 轮询控制 取出Loop池中的 从属Reactor
    // 主Reactor: 仅仅用于监听套接字
    EventLoop *_baseloop;
    // 线程与从属Reactor
    std::vector<LoopThread *> _threads;
    std::vector<EventLoop *> _loops;

public:
    LoopThreadPool(EventLoop *baseloop) : _thread_count(0), _next_idx(0), _baseloop(baseloop) {}
    void SetThreadCount(int count) { _thread_count = count; }
    void Create()
    {
        if (_thread_count > 0)
        {
            // one thread one loop
            _threads.resize(_thread_count);
            _loops.resize(_thread_count);
            for (int i = 0; i < _thread_count; i++)
            {
                // 从LoopThread获取
                _threads[i] = new LoopThread();
                // one thread one loop
                _loops[i] = _threads[i]->GetLoop();
            }
        }
        return;
    }

    // 获取EventLoop
    EventLoop *NextLoop()
    {
        if (_thread_count == 0)
        {
            return _baseloop;
        }

        _next_idx = (_next_idx + 1) % _thread_count;
        return _loops[_next_idx];
    }
};

class Any
{
public:
    Any() : _content(NULL) {}
    /*为了能够接收所有类型的对象，因此将构造函数定义为⼀个模板函数*/
    template <typename T>
    Any(const T &val) : _content(new holder<T>(val)) {}
    Any(const Any &other) : _content(other._content ? other._content->clone()
                                                    : NULL) {}
    ~Any()
    {
        if (_content)
            delete _content;
    }
    const std::type_info &type() { return _content ? _content->type() : typeid(void); }
    Any &swap(Any &other)
    {
        std::swap(_content, other._content);
        return *this;
    }
    template <typename T>
    T *get()
    {
        assert(typeid(T) == _content->type());
        return &((holder<T> *)_content)->val;
    }
    template <typename T>
    Any &operator=(const T &val)
    {
        /*为val构建⼀个临时对象出来，然后进⾏交换，这样临时对象销毁的时候，顺带原先
        保存的placeholder也会被销毁*/
        Any(val).swap(*this);
        return *this;
    }
    Any &operator=(Any other)
    {
        /*这⾥要注意形参只是⼀个临时对象，进⾏交换后就会释放，所以交换后，原先保存的
        placeholder指针也会被销毁*/
        other.swap(*this);
        return *this;
    }

private:
    /*因为模板类编译时就会确定类型，因此*/
    class placeholder
    {
    public:
        virtual ~placeholder() {}
        virtual const std::type_info &type() = 0;
        virtual placeholder *clone() = 0;
    };
    /*当前的Any类中⽆法保存所有类型的对象，或者说不能整成模板类，因此声明⼀个holder
    模板类出来使⽤holder类来管理传⼊的对象*/
    /*⽽Any类只需要管理holder对象即可*/
    template <typename T>
    class holder : public placeholder
    {
    public:
        holder(const T &v) : val(v) {}
        ~holder() {}
        const std::type_info &type() { return typeid(T); }
        placeholder *clone() { return new holder(val); }

    public:
        T val;
    };
    placeholder *_content;
};

// class Any
// {
// public:
//     Any() : _content(nullptr) {}
//     ~Any()
//     {
//         if (_content)
//             delete _content;
//     }

//     template <typename T>
//     Any(const T &val) : _content(new holder<T>(val)) {}

//     // 拷贝构造、赋值
//     Any(const Any &other) : _content(other._content ? other._content->clone() : nullptr) {}

//     void swap(Any &other)
//     {
//         std::swap(_content, other._content);
//     }

//     template <typename T>
//     Any &operator=(const T &val)
//     {
//         // 为val构建⼀个临时对象出来，然后进⾏交换.
//         // 这样临时对象销毁的时候，顺带原先,保存的placeholder也会被销毁
//         Any(val).swap(*this);
//         return *this;
//     }

//     Any &operator=(Any &other)
//     {
//         // 这⾥要注意形参只是⼀个临时对象，进⾏交换后就会释放，
//         // 所以交换后，原先保存的placeholder指针也会被销毁
//         other.swap(*this);
//         return *this;
//     }

// public:
//     template <typename T> // any<T>.get()
//     T *get()
//     {
//         assert(typeid(T) == _content->type());
//         return &((holder<T> *)_content)->_val;
//     }

// private:
//     // 模板类编译时就会确定类型
//     class placeholder
//     {
//     public:
//         virtual ~placeholder() {}
//         virtual const std::type_info &type() = 0;
//         virtual placeholder *clone() = 0;
//     };

//     // 声明⼀个holder模板类出来使⽤holder类来管理传⼊的对象
//     // ⽽Any类只需要管理holder对象即可
//     template <typename T>
//     class holder : public placeholder
//     {
//     public:
//         holder(const T &v) : _val(v) {}
//         ~holder() {}

//         virtual const std::type_info &type() { return typeid(T); }
//         virtual placeholder *clone() { return new holder(_val); }
//         T _val;
//     };
//     // Any只需要用一个父类指针管理
//     placeholder *_content;
// };

class Connection;
typedef enum
{
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    DISCONNECTING
} ConnStatu;

using PtrConnection = std::shared_ptr<Connection>;
class Connection : public std::enable_shared_from_this<Connection>
{
private:
    uint64_t _conn_id; // 连接的唯⼀ID，便于连接的管理和查找
    // 这里简便让 _conn_id作为定时器ID
    int _sockfd;                   // 连接关联的⽂件描述符
    bool _enable_inactive_release; // 连接是否启动⾮活跃销毁的判断标志，默认为false
    ConnStatu _status;             // 连接状态

    EventLoop *_loop;   // 这个连接关联的loop
    Socket _socket;     // 套接字管理
    Channel _channel;   // 连接的事件管理
    Buffer _in_buffer;  // 输⼊缓冲区---存放从socket中读取到的数据
    Buffer _out_buffer; // 输出缓冲区---存放要发送给对端的数据

    Any _context; // 请求的接收处理上下⽂

    // 这四个回调函数，是让服务器模块来设置的
    using ConnectedCallback = std::function<void(const PtrConnection &)>;
    using MessageCallback = std::function<void(const PtrConnection &, Buffer *)>;
    using ClosedCallback = std::function<void(const PtrConnection &)>;
    using AnyEventCallback = std::function<void(const PtrConnection &)>;

    ConnectedCallback _connected_callback;
    MessageCallback _message_callback;
    ClosedCallback _closed_callback;
    AnyEventCallback _event_callback;

    // 服务器会进行Connection的管理 这里是 从服务器删除该connection信息
    ClosedCallback _server_closed_callback;

private:
    // 五个channel的事件回调函数
    // 描述符可读事件触发后调⽤的函数，接收socket数据放到接收缓冲区中，然后调⽤_message_callback
    void HandlerRead()
    {
        // 1.接收socket的数据，放到缓冲区
        char buf[65536];
        ssize_t ret = _socket.Recv_NonBlock(buf, 65535);
        if (ret < 0)
        {
            // 出错了,不能直接关闭连接
            return ShutdownInLoop();
        }
        // 0表示的是没有读取到数据
        // -1表示连接断开
        // 更新缓冲区数据
        _in_buffer.WriteAndPush(buf, ret);

        // 调⽤message_callback进⾏业务处理
        if (_in_buffer.ReadAbleSize() > 0)
        {
            return _message_callback(shared_from_this(), &_in_buffer);
        }
    }

    // 描述符可写事件触发后调⽤的函数，将发送缓冲区中的数据进⾏发送
    void HandlerWrite()
    {
        //_out_buffer中保存的数据就是要发送的数据
        ssize_t ret = _socket.Send_NonBlock(_out_buffer.ReadPosition(), _out_buffer.ReadAbleSize());
        if (ret < 0)
        {
            // 发送错误就该关闭连接了
            if (_in_buffer.ReadAbleSize() > 0)
            {
                // 数据没有发送完 就把剩余的发送
                _message_callback(shared_from_this(), &_in_buffer);
            }
            return Release(); // 这时候就是实际的关闭释放操作了
        }

        // 注: 这里读偏移
        _out_buffer.MoveReadOffset(ret);
        if (_out_buffer.ReadAbleSize() == 0)
        {
            // 要发送的缓冲区没数据了 关闭监控
            _channel.DisableWrite();

            // 如果当前是连接待关闭状态，则有数据，发送完数据释放连接，没有数据则直接释放
            if (_status == DISCONNECTING)
            {
                return Release();
            }
        }
        return;
    }

    // 描述符触发挂断事件
    void HandleClose()
    {
        // ⼀旦连接挂断了，套接字就什么都⼲不了了，因此有数据待处理就处理⼀下，完毕关闭连接
        if (_in_buffer.ReadAbleSize() > 0)
        {
            _message_callback(shared_from_this(), &_in_buffer);
        }
        return Release();
    }

    // 描述符触发出错事件
    void HandlerError()
    {
        HandleClose();
    }

    // 描述符触发任意事件: 1. 刷新连接的活跃度--延迟定时销毁任务； 2. 调⽤组件使⽤者的任意事件回调
    void HandlerEvent()
    {
        if (_enable_inactive_release == true)
        {
            _loop->TimerRefresh(_conn_id);
        }
        if (_event_callback)
            _event_callback(shared_from_this());
    }

    // 启动⾮活跃连接超时释放规则
    void EnableInactiveReleaseInLoop(int sec)
    {
        _enable_inactive_release = true;
        // 如果当前定时销毁任务已经存在，那就刷新延迟⼀下即可
        if (_loop->HasTimer(_conn_id))
            return _loop->TimerRefresh(_conn_id);

        // 如果不存在定时销毁任务，则新增
        _loop->TimerAdd(_conn_id, sec, std::bind(&Connection::Release, this));
    }

    void CancelInactiveReleaseInLoop()
    {
        _enable_inactive_release = false;
        if (_loop->HasTimer(_conn_id))
        {
            _loop->TimerCancel(_conn_id);
        }
    }

    // 连接获取之后，所处的状态下要进⾏各种设置（启动读监控,调⽤回调函数）
    void EstablishedInLoop()
    {
        assert(_status == CONNECTING); // 当前一定是处于半连接状态下
        _status = CONNECTED;
        // ⼀旦启动读事件监控就有可能会⽴即触发读事件，如果这时候启动了⾮活跃连接销毁
        _channel.EnableRead();
        if (_connected_callback)
        {
            _connected_callback(shared_from_this());
        }
    }

    // 这个关闭操作并⾮实际的连接释放操作，需要判断还有没有数据待处理，待发送
    void ShutdownInLoop()
    {
        // 设置连接为半关闭状态
        _status = DISCONNECTING;
        // 处理业务逻辑没有处理的数据
        if (_in_buffer.ReadAbleSize() > 0)
        {
            if (_message_callback)
            {
                _message_callback(shared_from_this(), &_in_buffer);
            }
        }

        // 要么就是写⼊数据的时候出错关闭，要么就是没有待发送数据，直接关闭
        // 这里是真正发送数据
        if (_out_buffer.ReadAbleSize() > 0)
        {
            if (_channel.WriteAble() == false)
            {
                _channel.EnableWrite();
            }
        }

        if (_out_buffer.ReadAbleSize() == 0)
        {
            Release();
        }
    }

    // 实际释放窗口
    void ReleaseInLoop()
    {
        _status = DISCONNECTED;
        _channel.Remove();
        _socket.Close();

        // 如果当前定时器队列中还有定时销毁任务，则取消任务
        if (_loop->HasTimer(_conn_id))
        {
            CancelInactiveReleaseInLoop();
        }

        // 调⽤关闭回调函数，避免先移除服务器管理的连接信息导致Connection被释，
        // 此时去处理会出错，因此先调⽤⽤⼾的回调函数
        if (_closed_callback)
            _closed_callback(shared_from_this());

        // 移除服务器内部管理的连接信息
        if (_server_closed_callback)
            _server_closed_callback(shared_from_this());
    }

    // 这个接⼝并不是实际的发送接⼝，⽽只是把数据放到了发送缓冲区，启动了可写事件监控
    void SendInLoop(Buffer &buf)
    {
        if (_status == DISCONNECTED)
            return;
        _out_buffer.WriteBuffer(buf);
        if (_channel.WriteAble() == false)
        {
            _channel.EnableWrite();
        }
    }

    // 切换协议 重新设置函数
    void UpgradeInLoop(const Any &context,
                       const ConnectedCallback &conn,
                       const MessageCallback &msg,
                       const ClosedCallback &closed,
                       const AnyEventCallback &event)
    {
        _context = context;
        _connected_callback = conn;
        _message_callback = msg;
        _closed_callback = closed;
        _event_callback = event;
    }

public:
    Connection(EventLoop *loop, uint64_t conn_id, int sockfd) : _conn_id(conn_id), _sockfd(sockfd),
                                                                _enable_inactive_release(false), _loop(loop),
                                                                _status(CONNECTING), _socket(_sockfd),
                                                                _channel(loop, _sockfd)
    {
        _channel.SetReadCallback(std::bind(&Connection::HandlerRead, this));
        _channel.SetWriteCallback(std::bind(&Connection::HandlerWrite, this));

        _channel.SetCloseCallback(std::bind(&Connection::HandleClose, this));
        _channel.SetErrorCallback(std::bind(&Connection::HandlerError, this));
        _channel.SetEventCallback(std::bind(&Connection::HandlerEvent, this));
    }

    ~Connection() { DBG_LOG("RELEASE CONNECTION:%p", this); }

    // 获取文件描述符
    int get_fd() { return _sockfd; }
    // 获取id
    uint64_t get_id() { return _conn_id; }
    // 连接状态
    bool Connected() { return _status == CONNECTED; }
    // 设置上下⽂--连接建⽴完成时进⾏调⽤
    void SetContext(const Any &context) { _context = context; }
    // 获取上下⽂，返回的是指针
    Any *GetContext() { return &_context; }

    // using ConnectedCallback = std::function<void(const PtrConnection &)>;
    // using MessageCallback = std::function<void(const PtrConnection &, Buffer *)>;
    // using ClosedCallback = std::function<void(const PtrConnection &)>;
    // using AnyEventCallback = std::function<void(const PtrConnection &)>;
    // ConnectedCallback _connected_callback;
    // MessageCallback _message_callback;
    // ClosedCallback _closed_callback;
    // AnyEventCallback _event_callback;

    void SetConnectedCallback(const ConnectedCallback &cb) { _connected_callback = cb; }
    void SetMessageCallback(const MessageCallback &cb) { _message_callback = cb; }
    void SetAnyEventCallback(const AnyEventCallback &cb) { _event_callback = cb; }
    void SetClosedCallback(const ClosedCallback &cb) { _closed_callback = cb; }
    void SetSrvClosedCallback(const ClosedCallback &cb) { _server_closed_callback = cb; }

    // 发送数据，将数据放到发送缓冲区，启动写事件监控
    void Send(const char *data, size_t len)
    {
        // 外界传⼊的data，可能是个临时的空间，我们现在只是把发送操作压⼊了任务池，有可能并没有被⽴即执⾏
        // 因此有可能执⾏的时候，data指向的空间有可能已经被释放了
        Buffer buf;
        buf.WriteAndPush(data, len);
        // 右值引用 --> 提升效率
        _loop->RunInLoop(std::bind(&Connection::SendInLoop, this, std::move(buf)));
    }

    // 连接建⽴就绪后，进⾏channel回调设置 启动读监控
    void Established()
    {
        _loop->RunInLoop(std::bind(&Connection::EstablishedInLoop, this));
    }

    // 提供给组件使⽤者的关闭接⼝--并不实际关闭，需要判断有没有数据待处理
    void Shutdown()
    {
        _loop->RunInLoop(std::bind(&Connection::ShutdownInLoop, this));
    }

    void Release()
    {
        _loop->QueueInLoop(std::bind(&Connection::ReleaseInLoop, this));
    }

    // 启动⾮活跃销毁，并定义多⻓时间⽆通信就是⾮活跃，添加定时任务
    void EnableInactiveRelease(int sec)
    {
        _loop->RunInLoop(std::bind(&Connection::EnableInactiveReleaseInLoop, this, sec));
    }

    void CancelInactiveRelease()
    {
        _loop->RunInLoop(std::bind(&Connection::CancelInactiveReleaseInLoop, this));
    }

    void Upgrade(const Any &context,
                 const ConnectedCallback &conn,
                 const MessageCallback &msg,
                 const ClosedCallback &closed,
                 const AnyEventCallback &event)
    {
        // 这是一个非线程安全的
        // 当底层拿到数据，上层进行协议切换，这个行为被压入队列之中，
        // 如果此时遇到新的事件发生，读取的数据仍然会按照切换协议之前的格式进行解读
        _loop->AssertInLoop();
        _loop->RunInLoop(std::bind(&Connection::UpgradeInLoop, this, context, conn, msg, closed, event));
    }
};

// 获取连接管理
class Acceptor
{
private:
    // ⽤于创建监听套接字
    Socket _socket;
    // ⽤于对监听套接字进⾏事件监控
    EventLoop *_loop;
    // ⽤于对监听套接字进⾏事件管
    Channel _channel;
    // 读取新连接的回调函数 --> 这里的回调是创建Connection
    using AcceptCallback = std::function<void(int)>;
    AcceptCallback _accept_callback;

public:
    // 监听套接字的读事件回调处理函数---获取新连接，调⽤_accept_callback函数进⾏新连接处理
    void HandlerRead()
    {
        int newfd = _socket.Accept();
        if (newfd < 0)
        {
            return;
        }
        if (_accept_callback)
            _accept_callback(newfd);
    }

    int CreateServer(uint16_t port)
    {
        bool ret = _socket.CreateServer(port);
        assert(ret == true);
        return _socket.get_fd();
    }

public:
    Acceptor(EventLoop *loop, uint16_t port) : _socket(CreateServer(port)), _loop(loop),
                                               _channel(loop, _socket.get_fd())
    {
        _channel.SetReadCallback(std::bind(&Acceptor::HandlerRead, this));
    }

    void SetAcceptCallback(const AcceptCallback &cb) { _accept_callback = cb; }
    // 启动监控
    void Listen() { _channel.EnableRead(); }
};

class TcpServer
{
private:
    // 自增长id
    uint64_t _next_id;
    uint16_t _port;
    int _timeout;                  // 保存管理所有连接对应的shared_ptr对象
    bool _enable_inactive_release; // 是否启动了⾮活跃连接超时销毁的判断标志

    // 这是主线程的EventLoop对象，负责监听事件的处理
    // 这是监听套接字的管理对象
    EventLoop _baseloop;
    Acceptor _acceptor;
    LoopThreadPool _pool;                               // 这是从属EventLoop线程池
    std::unordered_map<uint64_t, PtrConnection> _conns; // 保存管理所有连接对应的shared_ptr对象

    // 回调函数
    using ConnectedCallback = std::function<void(const PtrConnection &)>;
    using ClosedCallback = std::function<void(const PtrConnection &)>;
    using MessageCallback = std::function<void(const PtrConnection &, Buffer *)>;
    using AnyEventCallback = std::function<void(const PtrConnection &)>;
    using Functor = std::function<void()>;

    ConnectedCallback _connected_callback;
    ClosedCallback _closed_callback;
    MessageCallback _message_callback;
    AnyEventCallback _event_callback;

private:
    // ⽤于添加⼀个定时任务
    void RunAfterInLoop(const Functor &task, int delay)
    {
        _next_id++;
        _baseloop.TimerAdd(_next_id, delay, task);
    }

    // 为新连接构造⼀个Connection进⾏管理
    void NewConnection(int fd)
    {
        _next_id++;
        PtrConnection conn(new Connection(_pool.NextLoop(), _next_id, fd));
        conn->SetMessageCallback(_message_callback);
        conn->SetClosedCallback(_closed_callback);
        conn->SetConnectedCallback(_connected_callback);
        conn->SetAnyEventCallback(_event_callback);

        conn->SetSrvClosedCallback(std::bind(&TcpServer::RemoveConnection, this, std::placeholders::_1));
        // 启动⾮活跃超时销毁
        if (_enable_inactive_release)
        {
            conn->EnableInactiveRelease(_timeout);
        }

        // 启动监控
        conn->Established();
        _conns.insert(std::make_pair(_next_id, conn));
    }

    // 从管理Connection的_conns中移除连接信息  ---> 需要bind到Connection内
    void RemoveConnectionInLoop(const PtrConnection &conn)
    {
        int id = conn->get_id();
        auto iter = _conns.find(id);
        if (iter != _conns.end())
        {
            _conns.erase(iter);
        }
    }

    void RemoveConnection(const PtrConnection &conn)
    {
        _baseloop.RunInLoop(std::bind(&TcpServer::RemoveConnectionInLoop, this, conn));
    }

public:
    TcpServer(int port) : _port(port),
                          _next_id(0),
                          _enable_inactive_release(false),
                          _acceptor(&_baseloop, _port),
                          _pool(&_baseloop)
    {
        _acceptor.SetAcceptCallback(std::bind(&TcpServer::NewConnection, this, std::placeholders::_1));
        // 监听事件启动 将监听套接字挂到baseloop上
        _acceptor.Listen();
    }
    void SetThreadCount(int count) { return _pool.SetThreadCount(count); }

    void SetConnectedCallback(const ConnectedCallback &cb) { _connected_callback = cb; }
    void SetMessageCallback(const MessageCallback &cb) { _message_callback = cb; }
    void SetClosedCallback(const ClosedCallback &cb) { _closed_callback = cb; }
    void SetAnyEventCallback(const AnyEventCallback &cb) { _event_callback = cb; }

    void EnableInactiveRelease(int timeout)
    {
        _timeout = timeout;
        _enable_inactive_release = true;
    }

    // ⽤于添加⼀个定时任务
    void RunAfter(const Functor &task, int delay)
    {
        _baseloop.RunInLoop(std::bind(&TcpServer::RunAfterInLoop, this, task, delay));
    }

    void Start()
    {
        _pool.Create();
        _baseloop.Start();
    }
};
