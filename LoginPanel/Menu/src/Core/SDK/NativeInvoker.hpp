#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>

namespace FiveM {

    // Native context for parameter passing
    struct NativeContext {
        void* returnValue;
        uint32_t argumentCount;
        void* arguments;
        uint32_t dataCount;
        uint64_t* vectorSpace;
    };

    // Native handler function pointer
    typedef void(*NativeHandler)(NativeContext* context);

    // Native invoker class
    class NativeInvoker {
    private:
        static NativeContext context;
        static uint64_t arguments[32];
        static uint64_t returnValue;

    public:
        // Initialize the native invoker
        static bool Initialize();

        // Get native handler by hash
        static NativeHandler GetHandler(uint64_t hash);

        // Invoke a native
        static uint64_t Invoke(uint64_t hash, const std::vector<uint64_t>& args);

        // Push argument
        template<typename T>
        static void PushArg(T value) {
            if (context.argumentCount < 32) {
                arguments[context.argumentCount++] = *(uint64_t*)&value;
            }
        }

        // Get return value
        template<typename T>
        static T GetReturn() {
            return *(T*)&returnValue;
        }

    private:
        // Find the native handler table
        static void* FindNativeTable();
    };

    // Helper function to invoke natives
    uint64_t InvokeNative(uint64_t hash, const std::vector<uint64_t>& args);
}
