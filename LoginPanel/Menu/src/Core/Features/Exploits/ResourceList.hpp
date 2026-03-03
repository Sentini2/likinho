#pragma once
#include <Includes/Includes.hpp>
#include <Includes/Utils.hpp>
#include <Core/Offsets.hpp>
#include <Core/Core.hpp>
#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <mutex>

namespace Core
{
	namespace Features
	{
		namespace Exploits
		{

			enum eResourceState : uint32_t {
				Uninitialized,
				Stopped,
				Starting,
				Started,
				Stopping
			};

			struct Resources_t {
				uintptr_t Pointer = 0;
				std::string Path;
				eResourceState State = eResourceState::Uninitialized;
			};

			inline std::vector<Resources_t> vResources;

			class cResourceList {
			private:
				uintptr_t ModuleBase = 0;
				uintptr_t ModuleBaseSize = 0;
				uintptr_t ResourceListEntry = 0;
				uintptr_t ResourceSigAddr = 0;
				uintptr_t StopResourceSigAddr = 0;
			private:
				//48 8B 05 ? ? ? ? 48 8D 14 F0
				std::vector<uint8_t> ResourceListSig = { 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x14, 0xF0 };
				//48 89 5C 24 ? 57 48 83 EC ? 48 8B F9 48 8B 89 ? ? ? ? E8 ? ? ? ? 83 BF
				std::vector<uint8_t> StopResourceSig = { 0x48, 0x89, 0x5C, 0x24, 0x00, 0x57, 0x48, 0x83, 0xEC, 0x00, 0x48, 0x8B, 0xF9, 0x48, 0x8B, 0x89, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0xBF };
			public:
				void Stop(uintptr_t ResourcePtr)
				{
					if (!ModuleBase || !ModuleBaseSize)
						ModuleBase = Mem.GetModuleBaseAddr(Mem.ProcId, xorstr("citizen-resources-core.dll"), &ModuleBaseSize);

					std::vector<uint8_t> ShellCode =
					{
						0x51, // push rcx
						0x48, 0xB9, // mov rcx, ResourcePtr
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ResourcePtr @ 3
						0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08, // call qword ptr Func
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Func @ 19
						0x59, // pop rcx
						0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,0x1
						0xC3 // ret
					};


					uintptr_t Cave = Mem.CreateCodeCave(ShellCode.size());

					if (!StopResourceSigAddr)
					{
						StopResourceSigAddr = Mem.FindSignatureBypass(StopResourceSig, ModuleBase, ModuleBaseSize);

						//std::cout << std::hex << StopResourceSigAddr << std::endl;
					}

					//std::cout << std::hex << ResourcePtr << std::endl;
					//sstd::cout << std::hex << Cave << std::endl;

					memcpy(ShellCode.data() + 3, &ResourcePtr, sizeof(ResourcePtr));
					memcpy(ShellCode.data() + 19, &StopResourceSigAddr, sizeof(StopResourceSigAddr));

					Mem.WriteBytes(Cave, ShellCode);

					HANDLE RemoteThread = CreateRemoteThread(Mem.ProcHandle, NULL, 0, (LPTHREAD_START_ROUTINE)Cave, NULL, 0, NULL);

					Sleep(1000);

					Mem.FreeCave(Cave);
				}

				void List()
				{
					while (true)
					{
						if (g_MenuInfo.IsOpen)
						{

							if (!ModuleBase || !ModuleBaseSize)
								ModuleBase = Mem.GetModuleBaseAddr(Mem.ProcId, xorstr("citizen-resources-core.dll"), &ModuleBaseSize);

							if (!ResourceSigAddr)
								ResourceSigAddr = Mem.FindSignatureBypass(ResourceListSig, ModuleBase, ModuleBaseSize);

							if (!ResourceListEntry)
								ResourceListEntry = Mem.Read<uintptr_t>(ResourceSigAddr + Mem.Read<int>(ResourceSigAddr + 3) + 7);

							size_t ListSize = vResources.size();
							size_t Idx = 0;

							for (size_t i = 0; i < 300; i++)
							{
								uintptr_t pResource = Mem.Read<uintptr_t>(ResourceListEntry + (i * 8U));
								if (!pResource)
									continue;

								uintptr_t Path = Mem.Read<uintptr_t>(pResource + 0xF0);
								std::string PathName = Mem.ReadString(Path + 0x0);
								if (PathName.empty()) continue;
								if (PathName.find(xorstr("resources:/")) == std::string::npos) continue;

								uint32_t State = Mem.Read<uint32_t>(pResource + 0x118);
								if (State < eResourceState::Uninitialized || State > eResourceState::Stopping) continue;

								Resources_t Resource;
								Resource.Pointer = pResource;
								Resource.Path = PathName;
								Resource.State = (eResourceState)State;

								if (Idx < ListSize)
									vResources[Idx] = Resource;
								else
									vResources.push_back(Resource);

								Idx++;

							}

							if (Idx < ListSize) vResources.resize(Idx);
						}

						std::this_thread::sleep_for(std::chrono::milliseconds(500));
					}
				}
			};

			inline cResourceList g_ResourceList;

		}

	}
}