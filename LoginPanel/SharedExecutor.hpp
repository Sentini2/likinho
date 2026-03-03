#pragma once
#include <Windows.h>

#define SHARED_MEM_NAME "LiKinhoExecutorShared"
#define SHARED_MEM_SIZE 10485760

struct SharedExecutorData {
    bool dllReady;
    bool resourceReady;
    bool executeFlag;
    bool resetFlag;
    int selectedResource;
    char scriptBuffer[10400000];
    char customPrefix[64];
    char resourceName[128];
    char statusMessage[256];
};

inline HANDLE CreateSharedMemory(bool isDll) {
    HANDLE hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, SHARED_MEM_SIZE, SHARED_MEM_NAME);
    return hMap;
}

inline SharedExecutorData* MapSharedMemory(HANDLE hMap) {
    if (!hMap) return nullptr;
    return (SharedExecutorData*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_MEM_SIZE);
}


