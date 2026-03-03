#pragma once
#include <windows.h>
#include <iostream>

#include <Security/xorstr.hpp>
#include <Security/Api/json.hpp>
#include <Globals.hpp>

#define CURL_STATIC_LIB
#include <Security/Api/curl/curl.h>
#pragma comment( lib, "ws2_32.lib" )
#pragma comment( lib, "Normaliz.lib" )
#pragma comment( lib, "Crypt32.lib" )
#pragma comment( lib, "Wldap32.lib" )
#pragma comment( lib, "libcurl.lib" )

class c_api {
private:
	using json = nlohmann::json;
	const std::string api_ip = xorstr( "https://sentini555.onrender.com/" );
	const std::string suser_agent = xorstr( "LiKinho-Client" );
	const std::string authorization_key = xorstr( "likinho-client-auth-2024" );
	const std::string enc_key = xorstr( "" );

	static inline auto write_callback( void * contents, size_t size, size_t nmemb, void * userp ) -> size_t {
		( ( std::string * ) userp )->append( ( char * ) contents, size * nmemb );
		return size * nmemb;
	}

public:
	inline auto report( std::string process_name, std::string threat_type, std::string screenshot_base64 = "" ) -> void {

		std::string response;

		CURL * hnd = curl_easy_init( );
		if ( !hnd ) return;

		std::string url = api_ip + xorstr( "api/security/report" );
		std::string user_agent = xorstr( "User-Agent: " ) + suser_agent;

		// Try to get token from globals or temp file? 
		// For now, let's look at how LoginPanel sets it.
		// KeyAuth server expects 'x-auth-token'.
		// In FiveM Menu, we might not have the token yet if it's right at startup.
		// However, AntiCrack runs in a thread.
		
		std::string auth_header = xorstr( "x-auth-token: " ) + g_MenuInfo.server_response; // Placeholder, assuming it's stored here

		curl_easy_setopt( hnd, CURLOPT_CUSTOMREQUEST, xorstr( "POST" ) );
		curl_easy_setopt( hnd, CURLOPT_URL, url.c_str( ) );

		struct curl_slist * headers = NULL;
		headers = curl_slist_append( headers, xorstr( "Content-Type: application/json" ) );
		headers = curl_slist_append( headers, user_agent.c_str( ) );
		headers = curl_slist_append( headers, auth_header.c_str( ) );
		curl_easy_setopt( hnd, CURLOPT_HTTPHEADER, headers );
		curl_easy_setopt( hnd, CURLOPT_WRITEFUNCTION, write_callback );
		curl_easy_setopt( hnd, CURLOPT_WRITEDATA, &response );

		json data;
		data[ xorstr( "username" ) ] = g_Variables.UserName.empty() ? "unauthenticated_user" : g_Variables.UserName;
		data[ xorstr( "process_name" ) ] = process_name;
		data[ xorstr( "threat_type" ) ] = threat_type;
		data[ xorstr( "screenshot_base64" ) ] = screenshot_base64;

		std::string sdata = data.dump( );
		curl_easy_setopt( hnd, CURLOPT_POSTFIELDS, sdata.c_str( ) );

		curl_easy_perform( hnd );
		curl_easy_cleanup( hnd );
		curl_slist_free_all( headers );
	}
	struct stc_application {
		const std::string version = xorstr( "1.0" );
		const std::string app_id = xorstr( "wexize_1" );
	} application;

	struct stc_client {

		std::string username;
		std::string discord_id;
		std::string hwid;
		std::string role;
		bool banned;

		struct stc_sub_type {
			std::string game_id;
			std::string type;
			bool active;
			std::string expire_date;
		} sub_type;

	} client;


	static std::string xorr( const std::string & toEncrypt, const char * key, size_t key_len )
	{
		std::string output = toEncrypt;
		for ( size_t i = 0; i < toEncrypt.size( ); i++ )
			output[ i ] = toEncrypt[ i ] ^ key[ i % key_len ];
		return output;
	}

	std::string parse_date( const std::string & data ) {
		std::tm tm = {};
		std::istringstream ss( data );
		ss >> std::get_time( &tm, xorstr( "%Y-%m-%dT%H:%M:%S" ) );
		if ( ss.fail( ) ) {
			return "";
		}

		char buffer[ 100 ];
		std::strftime( buffer, sizeof( buffer ), xorstr( "%d/%m/%Y %H:%M:%S" ), &tm );

		return buffer;
	}


	inline auto setup( ) -> std::string {

		std::string response;

		CURL * hnd = curl_easy_init( );
		if ( !hnd ) {
			return xorstr( "failed to start connection." );
		}

		std::string url = api_ip + xorstr( "api/client/cheatauth/setup" );
		std::string user_agent = xorstr( "User-Agent: " ) + suser_agent;
		std::string auth_key = xorstr( "Authorization: " ) + authorization_key;

		curl_easy_setopt( hnd, CURLOPT_CUSTOMREQUEST, xorstr( "POST" ) );
		curl_easy_setopt( hnd, CURLOPT_URL, url.c_str( ) );

		struct curl_slist * headers = NULL;
		headers = curl_slist_append( headers, xorstr( "Content-Type: application/json" ) );
		headers = curl_slist_append( headers, user_agent.c_str( ) );
		headers = curl_slist_append( headers, auth_key.c_str( ) );
		curl_easy_setopt( hnd, CURLOPT_HTTPHEADER, headers );
		curl_easy_setopt( hnd, CURLOPT_WRITEFUNCTION, write_callback );
		curl_easy_setopt( hnd, CURLOPT_WRITEDATA, &response );

		json data;
		data[ xorstr( "Version" ) ] = application.version;

		std::string json_str = data.dump( );

		curl_easy_setopt( hnd, CURLOPT_POSTFIELDS, json_str.c_str( ) );

		CURLcode ret = curl_easy_perform( hnd );

		if ( ret == CURLE_OK ) {

			auto remove_quotes = [ ] ( std::string & str ) {
				str.erase( std::remove( str.begin( ), str.end( ), '"' ), str.end( ) );
				};

			//remove_quotes( response );

			//std::string jsonstr = xorr( misc.hex2str( response ), enc_key.c_str( ), enc_key.length( ) );

			json response_json = json::parse( response );

			return response_json[ xorstr( "message" ) ].get<std::string>( );
		}
		else {
			return xorstr( "failed to make request to server." );
		}
	}

	inline auto login( const std::string user_id, const std::string hwid ) -> std::string {

		std::string response;

		CURL * hnd = curl_easy_init( );
		if ( !hnd ) {
			return xorstr( "failed to start connection." );
		}

		std::string url = api_ip + xorstr( "api/client/cheatauth/login" );
		std::string user_agent = xorstr( "User-Agent: " ) + suser_agent;
		std::string auth_key = xorstr( "Authorization: " ) + authorization_key;

		curl_easy_setopt( hnd, CURLOPT_CUSTOMREQUEST, xorstr( "POST" ) );
		curl_easy_setopt( hnd, CURLOPT_URL, url.c_str( ) );

		struct curl_slist * headers = NULL;
		headers = curl_slist_append( headers, xorstr( "Content-Type: application/json" ) );
		headers = curl_slist_append( headers, user_agent.c_str( ) );
		headers = curl_slist_append( headers, auth_key.c_str( ) );
		curl_easy_setopt( hnd, CURLOPT_HTTPHEADER, headers );
		curl_easy_setopt( hnd, CURLOPT_WRITEFUNCTION, write_callback );
		curl_easy_setopt( hnd, CURLOPT_WRITEDATA, &response );

		json data;
		data[ xorstr( "DiscordId" ) ] = user_id;
		data[ xorstr( "Hwid" ) ] = hwid;

		std::string json = data.dump( );

		curl_easy_setopt( hnd, CURLOPT_POSTFIELDS, json.c_str( ) );

		CURLcode ret = curl_easy_perform( hnd );

		auto remove_quotes = [ ] ( std::string & str ) {
			str.erase( std::remove( str.begin( ), str.end( ), '"' ), str.end( ) );
			};

		//remove_quotes( response );

		//std::string jsonstr = xorr( misc.hex2str( response ), enc_key.c_str( ), enc_key.length( ) );

		auto req_data = json::parse( response );
		auto client_data = req_data[ xorstr( "data" ) ];
		if ( req_data[ xorstr( "message" ) ] == xorstr( "success" ) ) {

			client.discord_id = client_data[ xorstr( "_id" ) ].get<std::string>( );
			client.username = client_data[ xorstr( "Info" ) ][ xorstr( "UserName" ) ].get<std::string>( );
			client.hwid = client_data[ xorstr( "Info" ) ][ xorstr( "CheatHwid" ) ].get<std::string>( );
			client.banned = client_data[ xorstr( "Info" ) ][ xorstr( "Ban" ) ][ xorstr( "IsBanned" ) ].get<bool>( );
			client.role = client_data[ xorstr( "Info" ) ][ xorstr( "Role" ) ].get<std::string>( );

			auto SubscriptionsArray = client_data[ xorstr( "Subscriptions" ) ];
			bool HasSub = false;
			if ( !SubscriptionsArray.empty() )
			{
				for ( const auto & Sub : SubscriptionsArray )
				{
					auto Type = Sub[ xorstr( "Type" ) ].get<std::string>();
					auto Expired = Sub[ xorstr( "Expired" ) ].get<bool>();

					if ( Type == xorstr( "ExternalCheatFiveM" ) )
						HasSub = true;

					if ( HasSub && Expired )
					{
						exit( 0 );
					}
				}

			}
			else {
				exit( 1337 );
			}

			g_Variables.UserName = client.username;
			g_Variables.Role = client.role;

			g_Variables.g_VerifyLogin = 348975682703;
			g_Variables.g_bPassedByThisVerify = true;
		}

		return req_data[ xorstr( "message" ) ].get<std::string>( );
	}
};

inline c_api g_Api;

