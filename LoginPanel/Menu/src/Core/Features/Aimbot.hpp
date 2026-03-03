#pragma once
#include <Includes/Includes.hpp>
#include <Core/Offsets.hpp>
#include <Core/SDK/SDK.hpp>

inline void PrintVector3( const D3DXVECTOR3 & vector ) {
	std::cout << vector.x << '\\' << vector.y << '\\' << vector.z << '\n';
}


namespace Core
{
	namespace Features
	{
		class cAimbot 
		{
		private:
			void SetViewAngles( CPed * Ped, D3DXVECTOR3 BonePos );
		public:
			void Start( );
		};

		inline cAimbot g_Aimbot;
	}
}