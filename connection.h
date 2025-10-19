#ifndef LUANETWORKBINDING_CONNECTION_H
#define LUANETWORKBINDING_CONNECTION_H

class IAsyncConnection {
public:
    virtual ~IAsyncConnection() = default;
    virtual void Start(std::string r) = 0;
    virtual bool Poll() = 0;
    virtual std::string const& Response() = 0;

    static IAsyncConnection* Create(const char* host_name, unsigned short port);
};

#endif //LUANETWORKBINDING_CONNECTION_H