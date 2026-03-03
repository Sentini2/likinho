#pragma once
#include <Includes/Includes.hpp>
#include <Core/Offsets.hpp>
#include <Core/SDK/SDK.hpp>

namespace Core
{
	namespace Features
	{
		class cSilentAim 
		{
		private:
			static bool SilentAimInitialized;
		private:
			static std::uintptr_t StartAddy;
			std::uintptr_t SilentAimHook;
		private:
			std::vector<std::uint8_t> OriginalFuncTable;
			std::vector<std::uint8_t> SilentAimShell =
			{
				0xC7, 0x45, 0x07, //mov[rbp + 07]
				0x00, 0x00, 0x00, 0x00, //X Value

				0xC7, 0x45, 0x0B, //mov[rbp + 0B]
				0x00, 0x00, 0x00, 0x00, //Y Value

				0xC7, 0x45, 0x0F, //mov[rbp + 0F]
				0x00, 0x00, 0x00, 0x00, //Z Value

				0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, //jmp qword ptr
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 //addr
			};
		public:
			void InitializeSilentAim( );
			void RestoreSilent( );
			void HookSilent( );
		};

		inline cSilentAim g_SilentAim;

	}
}