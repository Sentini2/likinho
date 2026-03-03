$pathGui = 'Menu\src\Gui\Gui.cpp'
$contentGui = Get-Content -Raw -Encoding UTF8 $pathGui

# Remove DrawAdminWarning from the end
$contentGui = $contentGui -replace '\s*// Admin Warning: always renders even when menu is closed\s*Core::Features::g_Esp.DrawAdminWarning\(\);\s*', "`r`n`t"

# Insert DrawAdminWarning inside the ActiveWindow check
$findStr = "Features::g_Esp.DrawVehicle();"
$replaceStr = $findStr + "`r`n`r`n`t`t`t`t`t// Admin Warning: renders only when game is active`r`n`t`t`t`t`tCore::Features::g_Esp.DrawAdminWarning();"
$contentGui = $contentGui.Replace($findStr, $replaceStr)
$contentGui | Set-Content -Encoding UTF8 $pathGui

Write-Host "Gui.cpp fixed!"

$pathEsp = 'Menu\src\Core\Features\Esp.cpp'
$contentEsp = Get-Content -Raw -Encoding UTF8 $pathEsp

# Add the early return for empty admins
$findEmpty = "ImGuiWindowFlags panelFlags ="
$replaceEmpty = "if (admins.empty()) return;`r`n`r`n`t" + $findEmpty
$contentEsp = $contentEsp.Replace($findEmpty, $replaceEmpty)

# Replace the simple skeleton with the complex one
$simpleSkel = @"
		if ( Cfg->AdminSkeleton )
		{
			D3DXVECTOR3 HeadPos = Ped->GetBonePosDefault( 0 );
			D3DXVECTOR2 Head    = Core::SDK::Game::WorldToScreen( HeadPos );
			D3DXVECTOR3 FeetPos = Ped->GetBonePosDefault( 8 ) - D3DXVECTOR3( 0, 0, 1.2f );
			D3DXVECTOR2 Feet    = Core::SDK::Game::WorldToScreen( FeetPos );
			if ( Head.x > 0 && Head.y > 0 && Feet.x > 0 && Feet.y > 0 )
			{
				// Outlined glow line
				DrawList->AddLine( ImVec2( Head.x, Head.y ), ImVec2( Feet.x, Feet.y ), ImColor( 0, 0, 0, 180 ), 4.0f );
				DrawList->AddLine( ImVec2( Head.x, Head.y ), ImVec2( Feet.x, Feet.y ), adminCol, 2.0f );
				// Head circle
				DrawList->AddCircle( ImVec2( Head.x, Head.y ), 5.0f, ImColor( 0, 0, 0, 180 ), 24, 3.0f );
				DrawList->AddCircle( ImVec2( Head.x, Head.y ), 5.0f, adminCol, 24, 1.5f );
			}
		}
"@

$complexSkel = @"
		if ( Cfg->AdminSkeleton )
		{
			uintptr_t FragInstNMGta = Mem.Read<uintptr_t>( ( uintptr_t ) Ped + g_Offsets.m_FragInst );
			uintptr_t v9 = Mem.Read<uintptr_t>( FragInstNMGta + 0x68 );
			if ( v9 )
			{
				Core::SDK::Game::cSkeleton_t Skeleton;
				Skeleton.m_pSkeleton = Mem.Read<uintptr_t>( v9 + 0x178 );
				Skeleton.crSkeletonData.Ptr = Mem.Read<uintptr_t>( Skeleton.m_pSkeleton );
				Skeleton.crSkeletonData.m_Used = Mem.Read<unsigned int>( Skeleton.crSkeletonData.Ptr + 0x1A );
				Skeleton.crSkeletonData.m_NumBones = Mem.Read<unsigned int>( Skeleton.crSkeletonData.Ptr + 0x5E );
				Skeleton.crSkeletonData.m_BoneIdTable_Slots = Mem.Read<unsigned short>( Skeleton.crSkeletonData.Ptr + 0x18 );

				if ( Skeleton.crSkeletonData.m_BoneIdTable_Slots )
				{
					Skeleton.crSkeletonData.m_BoneIdTable = Mem.Read<uintptr_t>( Skeleton.crSkeletonData.Ptr + 0x10 );
					Skeleton.Arg1 = Mem.Read<D3DXMATRIX>( Mem.Read<uintptr_t>( Skeleton.m_pSkeleton + 0x8 ) );
					Skeleton.Arg2 = Mem.Read<uintptr_t>( Skeleton.m_pSkeleton + 0x18 );

					D3DXVECTOR3 PelvisPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_Pelvis, Skeleton );
					D3DXVECTOR3 NeckPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_Neck_1, Skeleton );
					D3DXVECTOR3 LeftUperarmPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_L_UpperArm, Skeleton );
					D3DXVECTOR3 RightUperarmPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_R_UpperArm, Skeleton );
					D3DXVECTOR3 RightFormArmPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_R_Forearm, Skeleton );
					D3DXVECTOR3 LeftFormArmPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_L_Forearm, Skeleton );
					D3DXVECTOR3 RightHandPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_R_Hand, Skeleton );
					D3DXVECTOR3 LeftHandPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_L_Hand, Skeleton );
					D3DXVECTOR3 LeftThighPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_L_Thigh, Skeleton );
					D3DXVECTOR3 LeftCalfPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_L_Calf, Skeleton );
					D3DXVECTOR3 RightThighPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_R_Thigh, Skeleton );
					D3DXVECTOR3 RightCalfPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_R_Calf, Skeleton );
					D3DXVECTOR3 LfootPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_L_Foot, Skeleton );
					D3DXVECTOR3 RfootPos = Core::SDK::Game::GetBonePosComplex( Ped, SKEL_R_Foot, Skeleton );

					D3DXVECTOR2 Pelvis = Core::SDK::Game::WorldToScreen( PelvisPos );
					D3DXVECTOR2 Neck = Core::SDK::Game::WorldToScreen( NeckPos );
					D3DXVECTOR2 LeftUperarm = Core::SDK::Game::WorldToScreen( LeftUperarmPos );
					D3DXVECTOR2 RightUperarm = Core::SDK::Game::WorldToScreen( RightUperarmPos );
					D3DXVECTOR2 RightFormArm = Core::SDK::Game::WorldToScreen( RightFormArmPos );
					D3DXVECTOR2 LeftFormArm = Core::SDK::Game::WorldToScreen( LeftFormArmPos );
					D3DXVECTOR2 RightHand = Core::SDK::Game::WorldToScreen( RightHandPos );
					D3DXVECTOR2 LeftHand = Core::SDK::Game::WorldToScreen( LeftHandPos );
					D3DXVECTOR2 LeftThigh = Core::SDK::Game::WorldToScreen( LeftThighPos );
					D3DXVECTOR2 LeftCalf = Core::SDK::Game::WorldToScreen( LeftCalfPos );
					D3DXVECTOR2 RightThigh = Core::SDK::Game::WorldToScreen( RightThighPos );
					D3DXVECTOR2 RightCalf = Core::SDK::Game::WorldToScreen( RightCalfPos );
					D3DXVECTOR2 Lfoot = Core::SDK::Game::WorldToScreen( LfootPos );
					D3DXVECTOR2 Rfoot = Core::SDK::Game::WorldToScreen( RfootPos );

					if ( Core::SDK::Game::IsOnScreen( Lfoot ) && Core::SDK::Game::IsOnScreen( Rfoot ) && 
						 Core::SDK::Game::IsOnScreen( Pelvis ) && Core::SDK::Game::IsOnScreen( Neck ) && 
						 Core::SDK::Game::IsOnScreen( LeftUperarm ) && Core::SDK::Game::IsOnScreen( RightUperarm ) && 
						 Core::SDK::Game::IsOnScreen( RightFormArm ) && Core::SDK::Game::IsOnScreen( LeftFormArm ) )
					{
						D3DXVECTOR3 HeadPos = Ped->GetBonePosDefault( 0 );
						D3DXVECTOR2 ScreenHead = Core::SDK::Game::WorldToScreen( HeadPos );

						DrawList->AddLine( ImVec2( RightUperarm.x, RightUperarm.y ), ImVec2( RightFormArm.x, RightFormArm.y ), adminCol, 2.0f );
						DrawList->AddLine( ImVec2( LeftUperarm.x, LeftUperarm.y ), ImVec2( LeftFormArm.x, LeftFormArm.y ), adminCol, 2.0f );
						DrawList->AddLine( ImVec2( RightFormArm.x, RightFormArm.y ), ImVec2( RightHand.x, RightHand.y ), adminCol, 2.0f );
						DrawList->AddLine( ImVec2( LeftFormArm.x, LeftFormArm.y ), ImVec2( LeftHand.x, LeftHand.y ), adminCol, 2.0f );
						DrawList->AddLine( ImVec2( ScreenHead.x, ScreenHead.y ), ImVec2( Neck.x, Neck.y ), adminCol, 2.0f );
						DrawList->AddLine( ImVec2( Neck.x, Neck.y ), ImVec2( Pelvis.x, Pelvis.y ), adminCol, 2.0f );
						DrawList->AddLine( ImVec2( Neck.x, Neck.y ), ImVec2( LeftUperarm.x, LeftUperarm.y ), adminCol, 2.0f );
						DrawList->AddLine( ImVec2( Neck.x, Neck.y ), ImVec2( RightUperarm.x, RightUperarm.y ), adminCol, 2.0f );
						DrawList->AddLine( ImVec2( Pelvis.x, Pelvis.y ), ImVec2( LeftThigh.x, LeftThigh.y ), adminCol, 2.0f );
						DrawList->AddLine( ImVec2( Pelvis.x, Pelvis.y ), ImVec2( RightThigh.x, RightThigh.y ), adminCol, 2.0f );
						DrawList->AddLine( ImVec2( LeftThigh.x, LeftThigh.y ), ImVec2( LeftCalf.x, LeftCalf.y ), adminCol, 2.0f );
						DrawList->AddLine( ImVec2( RightThigh.x, RightThigh.y ), ImVec2( RightCalf.x, RightCalf.y ), adminCol, 2.0f );
						DrawList->AddLine( ImVec2( LeftCalf.x, LeftCalf.y ), ImVec2( Lfoot.x, Lfoot.y ), adminCol, 2.0f );
						DrawList->AddLine( ImVec2( RightCalf.x, RightCalf.y ), ImVec2( Rfoot.x, Rfoot.y ), adminCol, 2.0f );
					}
				}
			}
		}
"@

$contentEsp = $contentEsp.Replace($simpleSkel, $complexSkel)
$contentEsp | Set-Content -Encoding UTF8 $pathEsp

Write-Host "Esp.cpp fixed!"
