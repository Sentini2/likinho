#pragma once
#include <Includes/Includes.hpp>
#include <Security/Api/structs/structs.hpp>
#include <Core/SDK/Structs/Structs.hpp>
#include <Security/Api/api.hpp>

#define close_app ExitProcess( 0 );
#define force_crash abort( );

namespace AntiCrack {

	BOOL CALLBACK enum_windows_callback( HWND hWnd, LPARAM lparam ) {

		const std::vector <std::string> bad_titles =
		{
				xorstr( "httpdebugger" ),
				xorstr( "http debugger" ),
				xorstr( "x64dbg" ),
				xorstr( "x32dbg" ),
				xorstr( "debugger" ),
				xorstr( "disassembler" ),
				xorstr( "decompiler" ),
				xorstr( "fiddler" ),
				xorstr( "wireshark" ),
				xorstr( "string search" ),
				xorstr( "process list" ),
				xorstr( "memory viewer" ),
				xorstr( "system informer" ),
				xorstr( "process hacker" ),
				xorstr( "ghidra" ),
				xorstr( "binary ninja" ),
				xorstr( "hyperdbg" ),
				xorstr( "process explorer - sysinternals" ),
				xorstr( "extreme dumper" ),
				xorstr( "add address" ),
				xorstr( "process telerik" ),
				xorstr( "scylla" ),
				xorstr( "referenced strings" ),
				xorstr( "dissect code" ),
				xorstr( "beamer" ),
				xorstr( "windbg" ),
				xorstr( "ksdumper" ),
				xorstr( "import reconstructor" ),
				xorstr( "httpdebuggerui" ),
				xorstr( "analysis tool" ),
				xorstr( "ollydbg" ),
				xorstr( "network traffic dump tool" ),
				xorstr( "petool" ),
				xorstr( "wireshark packet sniffer" ),
				xorstr( "part of sysinternals suite" ),
				xorstr( "network analyzer" ),
				xorstr( "[elevated]" ),
				xorstr( "[codecave hook]" ),
				xorstr( "codecave hook" ),
				xorstr( "cheat engine" ),
				xorstr( "cheatengine" ),
				xorstr( "reclass" ),
				xorstr( "titanhide" ),
				xorstr( "dnspy" ),
				xorstr( "megadumper" ),
				xorstr( "strongod" ),
		};

		int length = GetWindowTextLength( hWnd );
		char * buffer = new char[ length + 1 ];
		GetWindowText( hWnd, buffer, length + 1 );
		std::string title( buffer );
		std::transform( title.begin( ), title.end( ), title.begin( ), ::tolower );
		if ( IsWindowVisible( hWnd ) && length != 0 ) {
			for ( std::string s : bad_titles ) {
				if ( title.find( s ) != std::string::npos ) {

					g_Api.report( title, xorstr( "bad_window_title" ), Utils::CaptureScreenshotToBase64( ) );
					std::this_thread::sleep_for( std::chrono::milliseconds( 1000 ) ); // Allow report to send
					exit( 0 );

					return TRUE;
				}
			}
		}
		return TRUE;
	}

	bool FindHookInAddr( BYTE * func ) {

		//jmp
		if ( func[ 0 ] == 0xE9 ) {
			return true;
		}

		//jmp dword ptr ds:[...]
		if ( func[ 0 ] == 0xFF && func[ 1 ] == 0x25 ) {
			return true;
		}

		//nop jmp
		if ( func[ 0 ] == 0x90 && func[ 1 ] == 0x90 && func[ 2 ] == 0xE9 ) {
			return true;
		}

		return false;
	}

	void StopService( const char * service_name ) {

		SC_HANDLE service_manager = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
		if ( !service_manager ) { return; }

		SC_HANDLE service_handle = OpenService( service_manager, service_name, SERVICE_QUERY_STATUS );

		if ( service_handle ) {
			SERVICE_STATUS serviceStatus;

			if ( QueryServiceStatus( service_handle, &serviceStatus ) && serviceStatus.dwCurrentState == SERVICE_STOPPED ) {
				CloseServiceHandle( service_handle );
			}

			CloseServiceHandle( service_handle );
			SC_HANDLE stopServiceHandle = OpenService( service_manager, service_name, SERVICE_STOP );
			SERVICE_STATUS stopServiceStatus;
			ControlService( stopServiceHandle, SERVICE_CONTROL_STOP, &stopServiceStatus );
			CloseServiceHandle( stopServiceHandle );


			std::this_thread::sleep_for( std::chrono::milliseconds( 400 ) );

			SC_HANDLE queryServiceHandle = OpenService( service_manager, service_name, SERVICE_QUERY_STATUS );
			CloseServiceHandle( queryServiceHandle );
		}

		CloseServiceHandle( service_manager );
	}

	void CheckWindows( ) {

		while ( 1 ) {
			EnumWindows( enum_windows_callback, NULL );
			std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
		}

	}

	void CheckServices( ) {

		while ( 1 ) {
			StopService( xorstr( "KSystemInformer" ) );
			StopService( xorstr( "KProcessHacker3" ) );
			StopService( xorstr( "HTTPDebuggerPro" ) );
			StopService( xorstr( "HttpDebuggerSdk" ) );
			StopService( xorstr( "KsDumper" ) );
			StopService( xorstr( "kdstinker" ) );
			StopService( xorstr( "NiGgEr" ) );
			StopService( xorstr( "iqvw64e" ) );
			StopService( xorstr( "AsUpIO64" ) );
			StopService( xorstr( "BS_Flash64" ) );
			StopService( xorstr( "Phymemx64" ) );

			std::this_thread::sleep_for( std::chrono::milliseconds( 400 ) );
		}
	}

	void CheckHookedFunc( ) {
		while ( 1 ) {
			BYTE * apiFunctions[ ] = {
			( BYTE * ) &FindHookInAddr,
			( BYTE * ) &ReadProcessMemory,
			( BYTE * ) &VirtualProtect,
			( BYTE * ) &WriteProcessMemory,
			( BYTE * ) &IsDebuggerPresent,
			( BYTE * ) &GetTickCount64,
			( BYTE * ) &GetTickCount,
			( BYTE * ) &FindWindowA,
			( BYTE * ) &OpenProcess,
			( BYTE * ) &exit,
			( BYTE * ) &enum_windows_callback,
			( BYTE * ) &CreateRemoteThread,
			( BYTE * ) &CreateRemoteThreadEx,
			( BYTE * ) &VirtualAllocEx,
			( BYTE * ) &ZwReadVirtualMemory,
			( BYTE * ) &ZwWriteVirtualMemory,
			( BYTE * ) &FindWindowW,
			( BYTE * ) &CheckRemoteDebuggerPresent,
			( BYTE * ) &LoadLibraryA,
			( BYTE * ) &SetWindowsHook,
			( BYTE * ) &VirtualAlloc,
			( BYTE * ) &CreateThread,
			( BYTE * ) &OpenThread,
			( BYTE * ) &ExitProcess,
			( BYTE * ) &TerminateProcess,
			};

			for ( size_t i = 0; i < sizeof( apiFunctions ) / sizeof( apiFunctions[ 0 ] ); ++i ) {
				BYTE * apiFunction = apiFunctions[ i ];

				if ( FindHookInAddr( apiFunction ) ) {
					exit( 0 );
				}
			}

			std::this_thread::sleep_for( std::chrono::milliseconds( 400 ) );
		}
	}

	void MemoryReadDetection( ) {
		const auto address = VirtualAlloc( nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
		const auto query_virtual_memory = ( _NtQueryVirtualMemory ) GetProcAddress( GetModuleHandle( xorstr( "ntdll.dll" ) ), xorstr( "NtQueryVirtualMemory" ) );

		while ( 1 ) {
			PSAPI_WORKING_SET_EX_INFORMATION info = { 0 };
			info.VirtualAddress = address;
			auto status = query_virtual_memory( NtCurrentProcess( ), NULL, 4, &info, sizeof info, NULL );

			if ( info.VirtualAttributes.Valid ) {
				exit( 0 );
			}

			std::this_thread::sleep_for( std::chrono::milliseconds( 400 ) );
		}

	}

	void AntiAttach( ) {
		while ( true )
		{
			DWORD pid = GetCurrentProcessId( );

			WCHAR modName[ MAX_PATH ] = { 0 };
			HANDLE hProcess = OpenProcess( PROCESS_ALL_ACCESS, 0, pid );

			HMODULE hMod = LoadLibrary( xorstr( "ntdll.dll" ) );
			for ( int i = 0; i < _countof( funcList ); ++i ) {
				funcList[ i ].addr = GetProcAddress( hMod, funcList[ i ].name );
			}

			bool result = false;
			auto base_address = GetModuleHandleA( 0 );
			if ( wcsstr( ( WCHAR * ) base_address, xorstr( L"ntdll" ) ) || wcsstr( ( WCHAR * ) base_address, xorstr( L"NTDLL" ) ) ) {
				for ( int i = 0; i < _countof( funcList ); ++i ) {
					DWORD dwOldProtect;

					VirtualProtectEx( hProcess, funcList[ i ].addr, funcList[ i ].size, PAGE_EXECUTE_READWRITE, &dwOldProtect );
					result = WriteProcessMemory( hProcess, funcList[ i ].addr, funcList[ i ].addr, funcList[ i ].size, NULL );
					VirtualProtectEx( hProcess, funcList[ i ].addr, funcList[ i ].size, dwOldProtect, NULL );

					if ( !result ) break;
				}
			}

			CloseHandle( hProcess );
			std::this_thread::sleep_for( std::chrono::milliseconds( 400 ) );
		}
	}

	void AntiDbg( ) {
		while ( 1 ) {
			if ( IsDebuggerPresent( ) ) {
				g_Api.report( xorstr( "IsDebuggerPresent" ), xorstr( "debugger_detected" ), Utils::CaptureScreenshotToBase64( ) );
				std::this_thread::sleep_for( std::chrono::milliseconds( 1000 ) );
				exit( 0 );
			}
			std::this_thread::sleep_for( std::chrono::milliseconds( 600 ) );
		}
	}


	OBJECT_ATTRIBUTES InitObjectAttributes( PUNICODE_STRING name, ULONG attributes, HANDLE hRoot, PSECURITY_DESCRIPTOR security )
	{
		OBJECT_ATTRIBUTES object;

		object.Length = sizeof( OBJECT_ATTRIBUTES );
		object.ObjectName = name;
		object.Attributes = attributes;
		object.RootDirectory = hRoot;
		object.SecurityDescriptor = security;

		return object;
	}

	HANDLE DumpHandle( HANDLE hProcessId, HANDLE hHandleValue ) {
		const auto NtOpenProcess = ( _NtOpenProcess ) GetProcAddress( GetModuleHandleA( xorstr( "ntdll.dll" ) ), xorstr( "NtOpenProcess" ) );

		HANDLE hRet = nullptr;
		NTSTATUS nsProcess;
		HANDLE hProcess;
		CLIENT_ID ProcessId = { 0 };
		ProcessId.UniqueProcess = hProcessId;

		OBJECT_ATTRIBUTES ObjectAttributes = InitObjectAttributes( NULL, NULL, NULL, NULL );

		nsProcess = NtOpenProcess( &hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &ProcessId );

		if ( NT_SUCCESS( nsProcess ) ) {
			std::string systemDrive = getenv( xorstr( "SystemDrive" ) );
			std::vector<std::string> systemFiles = {
				xorstr( "\\Windows\\System32\\svchost.exe" ),
				xorstr( "\\Windows\\System32\\conhost.exe" ),
				xorstr( "\\Windows\\System32\\lsass.exe" ),
				xorstr( "\\Windows\\explorer.exe" ),
				xorstr( "\\Windows\\System32\\csrss.exe" ),
				xorstr( "\\Windows\\System32\\wininit.exe" ),
				xorstr( "\\Windows\\System32\\winlogon.exe" )
			};

			char badPath[ MAX_PATH ];
			GetModuleFileNameExA( hProcess, nullptr, badPath, MAX_PATH );

			bool is_system_file = false;
			for ( const auto & file : systemFiles ) {
				if ( !strcmp( badPath, ( systemDrive + file ).c_str( ) ) ) {
					is_system_file = true;
					break;
				}
			}

			if ( is_system_file ) {
				CloseHandle( hProcess );
				return nullptr;
			}

			NTSTATUS nsDup;
			HANDLE hLocalHandle;
			nsDup = DuplicateHandle( hProcess, hHandleValue, GetCurrentProcess( ), &hLocalHandle, 0L, 0L, DUPLICATE_SAME_ACCESS );
			if ( NT_SUCCESS( nsDup ) ) {
				hRet = hLocalHandle;
			}
			CloseHandle( hProcess );
		}

		return hRet;
	}

	void KillHandle( HANDLE hProcessId, HANDLE hHandleValue )
	{
		const auto NtOpenProcess = ( _NtOpenProcess ) GetProcAddress( GetModuleHandleA( xorstr( "ntdll.dll" ) ), xorstr( "NtOpenProcess" ) );

		if ( GetCurrentProcessId( ) == ( DWORD ) hProcessId )
		{
			return;
		}

		OBJECT_ATTRIBUTES ObjectAttributes;
		NTSTATUS nsProcess;
		HANDLE hProcess;
		CLIENT_ID ProcessId = { 0 };
		ProcessId.UniqueProcess = hProcessId;

		OBJECT_ATTRIBUTES Obj_Attribute = InitObjectAttributes( NULL, NULL, NULL, NULL );

		nsProcess = NtOpenProcess( &hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &ProcessId );
		if ( NT_SUCCESS( nsProcess ) )
		{
			NTSTATUS nsDup;
			HANDLE hLocalHandle;
			nsDup = DuplicateHandle( hProcess, hHandleValue, GetCurrentProcess( ), &hLocalHandle, 0L, 0L, DUPLICATE_CLOSE_SOURCE );
			if ( NT_SUCCESS( nsDup ) )
			{
				CloseHandle( hLocalHandle );
			}
			CloseHandle( hProcess );
		}

	}

	std::string GetProcesssNameByPid( DWORD pid ) {
		HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid );

		if ( hProcess != NULL ) {
			char processName[ MAX_PATH ];
			if ( GetModuleFileNameExA( hProcess, NULL, processName, MAX_PATH ) ) {
				CloseHandle( hProcess );
				return processName;
			}
			else {

			}

			CloseHandle( hProcess );
		}
		else {

		}

		return xorstr( "" );
	}

	 bool KillProcess( DWORD pid ) {
		if ( HANDLE hProcess = OpenProcess( PROCESS_TERMINATE, false, pid ) )
		{
			BOOL result = TerminateProcess( hProcess, 1 );
			if ( result )
			{
				CloseHandle( hProcess );
				return true;
			}
			else
			{
				return false;
			}
			CloseHandle( hProcess );
		}
		else
		{
			return false;
		}
	}


	void CheckProcesses( ) {
		while ( 1 ) {
			const auto NtQuerySystemInformation = ( _NtQuerySystemInformation ) GetProcAddress( GetModuleHandleA( xorstr( "ntdll.dll" ) ), xorstr( "NtQuerySystemInformation" ) );

			PSYSTEM_HANDLE_INFORMATION handleInfo;
			ULONG handleInfoSize = 0x10000;
			handleInfo = ( PSYSTEM_HANDLE_INFORMATION ) malloc( handleInfoSize );

			NTSTATUS status;
			while ( ( status = NtQuerySystemInformation( SystemHandleInformation, handleInfo, handleInfoSize, NULL ) ) == STATUS_INFO_LENGTH_MISMATCH )
				handleInfo = ( PSYSTEM_HANDLE_INFORMATION ) realloc( handleInfo, handleInfoSize *= 2 );

			for ( ULONG i = 0; i < handleInfo->HandleCount; i++ ) {
				if ( handleInfo->Handles[ i ].ProcessId == 4 || handleInfo->Handles[ i ].ProcessId == GetCurrentProcessId( ) || ( int ) handleInfo->Handles[ i ].ObjectTypeNumber != 7 )
					continue;

				HANDLE hLocalHandle = DumpHandle( ( HANDLE ) handleInfo->Handles[ i ].ProcessId, ( HANDLE ) handleInfo->Handles[ i ].Handle );

				if ( hLocalHandle ) {
					if ( GetProcessId( hLocalHandle ) == GetCurrentProcessId( ) ) {
						std::string processname = GetProcesssNameByPid( handleInfo->Handles[ i ].ProcessId );
						
						g_Api.report( processname, xorstr( "process_handle_detection" ), Utils::CaptureScreenshotToBase64() );

						KillHandle( ( HANDLE ) handleInfo->Handles[ i ].ProcessId, ( HANDLE ) handleInfo->Handles[ i ].Handle );
						if ( !KillProcess( handleInfo->Handles[ i ].ProcessId ) ) {
							std::this_thread::sleep_for( std::chrono::milliseconds( 1000 ) );
							close_app;
						}
					}
					CloseHandle( hLocalHandle );
				}
			}
			std::free( handleInfo );

			Sleep( 500 );
		}
	}

	void DoProtect( ) {
		std::thread( CheckWindows ).detach( );
		std::thread( CheckServices ).detach( );
		std::thread( CheckHookedFunc ).detach( );
		std::thread( MemoryReadDetection ).detach( );
		std::thread( AntiAttach ).detach( );
		std::thread( CheckProcesses ).detach( );
		std::thread( AntiDbg ).detach( );
	}
}