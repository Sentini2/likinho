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
			class cHandlingEditor 
			{
			private:
				CVehicle * CurrentVeh = nullptr;
				uintptr_t CurrentHandling = 0;
			public:
				float AccelerationDefault = 0.f;
				float BreakForceDefault = 0.f;
				float TractionCurveMinDefault = 0.f;
			public:
				float fAcceleration = 0.f;
				float fBreakForce = 0.f;
				float fTractionCurveMin = 0.f;
			private:
				void GetHandling( )
				{
					if ( !CurrentVeh )
						CurrentVeh = Core::SDK::Pointers::pLocalPlayer->GetLastVehicle( );

					if ( !CurrentHandling )
						CurrentHandling = CurrentVeh->GetHandling( );

					if ( !CurrentVeh || !CurrentHandling )
						return;
				}
			public:
				void ReadHandlingValues( )
				{
					GetHandling( );

					AccelerationDefault = Mem.Read<float>( CurrentHandling + offsetof( CHandlingData, m_acceleration ) );
					BreakForceDefault = Mem.Read<float>(CurrentHandling + offsetof(CHandlingData, m_brake_force));
					TractionCurveMinDefault = Mem.Read<float>( CurrentHandling + offsetof( CHandlingData, m_traction_curve_min ) );
					
				}

				void ApplyHandlingValues( )
				{
					GetHandling( );

					Mem.Write<float>( CurrentHandling + offsetof( CHandlingData, m_acceleration ), fAcceleration );
					Mem.Write<float>(CurrentHandling + offsetof(CHandlingData, m_brake_force), fBreakForce);
					Mem.Write<float>( CurrentHandling + offsetof( CHandlingData, m_traction_curve_min ), fTractionCurveMin );
					
				}

				void SaveHandlingValues( )
				{
					GetHandling( );

					AccelerationDefault = Mem.Read<float>( CurrentHandling + offsetof( CHandlingData, m_acceleration ) );
					BreakForceDefault = Mem.Read<float>(CurrentHandling + offsetof(CHandlingData, m_brake_force));
					TractionCurveMinDefault = Mem.Read<float>( CurrentHandling + offsetof( CHandlingData, m_traction_curve_min ) );

					fAcceleration = AccelerationDefault;
					fBreakForce = BreakForceDefault;
					fTractionCurveMin = TractionCurveMinDefault;
				}

				void RestoreHandlingValues( )
				{
					GetHandling( );

					Mem.Write<float>( CurrentHandling + offsetof( CHandlingData, m_acceleration ), AccelerationDefault );
					Mem.Write<float>(CurrentHandling + offsetof(CHandlingData, m_acceleration), BreakForceDefault);
					Mem.Write<float>( CurrentHandling + offsetof( CHandlingData, m_traction_curve_min ), TractionCurveMinDefault );

					fAcceleration = AccelerationDefault;
					fBreakForce = BreakForceDefault;
					fTractionCurveMin = TractionCurveMinDefault;
				}
			};

			inline cHandlingEditor g_HandlingEditor;
		}

	}
}