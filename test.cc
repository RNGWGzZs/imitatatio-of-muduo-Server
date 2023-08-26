// 测试timerwheel
#include "server.hpp"
int main()
{
    Socket cli_sock;
    cli_sock.CreateClient(8085, "127.0.0.1");
    for (int i = 0; i < 5; ++i)
    {
        std::string send_str = "test for timewheel";
        cli_sock.Send(send_str.c_str(), send_str.size());

        char buf[1024];
        cli_sock.Recv(buf, send_str.size());
        buf[send_str.size()] = 0;
        DBG_LOG("echo:%s", buf);
    }

    while (1)
    {
        DBG_LOG("不再进行通信...");
        sleep(1);
    }

    return 0;
}