extends Node
class_name SupabaseOAuthProvider
## OAuth flow handler for Supabase authentication providers.
##
## Handles OAuth authentication with Supabase providers (Discord, Google, etc.)
## by running a local TCP server to capture OAuth callbacks.

## Emitted when authentication succeeds with tokens.
signal auth_success(access_token: String, refresh_token: String, expires_in: int)

## Emitted when authentication fails with error details.
signal auth_error(error_code: String, error_description: String)

## Port for local OAuth callback server.
const OAUTH_CALLBACK_PORT: int = 3000

## Path to OAuth success page HTML template.
const SUCCESS_PAGE_PATH: String = "res://addons/supabase/oauth_pages/success.html"

## Path to OAuth error page HTML template.
const ERROR_PAGE_PATH: String = "res://addons/supabase/oauth_pages/error.html"

var _supabase_url: String = ""
var _tcp_server: TCPServer = TCPServer.new()
var _is_listening: bool = false


func _init(supabase_url: String) -> void:
	_supabase_url = supabase_url


## Starts the OAuth authentication flow for the specified provider.
## Opens the system browser and starts listening for the OAuth callback.
## @param provider: OAuth provider name (e.g., "discord", "google", "github")
func authenticate(provider: String = "discord") -> void:
	if _is_listening:
		push_warning("[SupabaseOAuth] OAuth flow already in progress")
		return

	# Start local server
	var err: Error = _tcp_server.listen(OAUTH_CALLBACK_PORT)
	if err != OK:
		auth_error.emit("server_error", "Failed to start local server on port %d" % OAUTH_CALLBACK_PORT)
		return

	_is_listening = true
	print("[SupabaseOAuth] Listening on port %d" % OAUTH_CALLBACK_PORT)

	# Build and open OAuth URL
	var oauth_url: String = _build_oauth_url(provider)
	print("[SupabaseOAuth] Opening: %s" % oauth_url)
	OS.shell_open(oauth_url)


## Cancels the current OAuth flow and stops listening.
func cancel() -> void:
	if _is_listening:
		_tcp_server.stop()
		_is_listening = false
		print("[SupabaseOAuth] Cancelled")


func _process(_delta: float) -> void:
	if _is_listening and _tcp_server.is_connection_available():
		_handle_callback()


## Builds the OAuth authorization URL for the given provider.
func _build_oauth_url(provider: String) -> String:
	var params: Dictionary = {
		&"provider": provider,
		&"redirect_to": "http://localhost:%d" % OAUTH_CALLBACK_PORT
	}

	var query_parts: Array[String] = []
	for key: StringName in params:
		query_parts.append("%s=%s" % [key, String(params[key]).uri_encode()])

	return _supabase_url + "/auth/v1/authorize?" + "&".join(query_parts)


## Handles incoming HTTP requests from OAuth callbacks.
func _handle_callback() -> void:
	var peer: StreamPeerTCP = _tcp_server.take_connection()
	if peer == null:
		return

	# Read HTTP request
	var request_data: String = ""
	while peer.get_available_bytes() > 0:
		request_data += peer.get_utf8_string(peer.get_available_bytes())
		await get_tree().create_timer(0.05).timeout

	# Parse request
	var lines: PackedStringArray = request_data.split("\n")
	if lines.size() == 0:
		peer.disconnect_from_host()
		return

	var request_line: String = lines[0]
	var request_path: String = ""
	var params: Dictionary = {}

	if " " in request_line:
		request_path = request_line.split(" ")[1].split("?")[0]

	if "?" in request_line:
		var query_string: String = request_line.split("?")[1].split(" ")[0]
		params = _parse_query_string(query_string)

	# Handle token callback from JavaScript
	if request_path == "/tokens" and params.has(&"access_token"):
		print("[SupabaseOAuth] ✅ Authentication successful")

		# Send response
		peer.put_data(_create_simple_response("Tokens received!").to_utf8_buffer())
		peer.disconnect_from_host()

		# Clean up
		_tcp_server.stop()
		_is_listening = false

		# Emit success
		auth_success.emit(
			params.get(&"access_token", ""),
			params.get(&"refresh_token", ""),
			int(params.get(&"expires_in", "3600"))
		)
		return

	# Initial redirect - serve token extraction page
	var response_html: String
	if params.has(&"error"):
		print("[SupabaseOAuth] ❌ Error: %s" % params.get(&"error_description", "Unknown"))
		response_html = _create_error_page(
			params.get(&"error", "unknown_error"),
			params.get(&"error_description", "An error occurred")
		)

		# Emit error after sending response
		var error_code: String = params.get(&"error", "unknown_error")
		var error_desc: String = params.get(&"error_description", "An error occurred")

		peer.put_data(_create_http_response(response_html).to_utf8_buffer())
		peer.disconnect_from_host()
		_tcp_server.stop()
		_is_listening = false

		auth_error.emit(error_code, error_desc)
	else:
		response_html = _create_token_extraction_page()
		peer.put_data(_create_http_response(response_html).to_utf8_buffer())
		peer.disconnect_from_host()


## Parses URL query string into a Dictionary.
func _parse_query_string(query: String) -> Dictionary:
	var params: Dictionary = {}
	var pairs: PackedStringArray = query.split("&")

	for pair: String in pairs:
		var kv: PackedStringArray = pair.split("=")
		if kv.size() == 2:
			params[StringName(kv[0])] = kv[1].uri_decode()

	return params


## Creates a complete HTTP response with the given HTML body.
func _create_http_response(body: String) -> String:
	return "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n" + body


## Creates a simple plain-text HTTP response.
func _create_simple_response(message: String) -> String:
	return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + message


## Loads and returns the OAuth success page HTML.
func _create_token_extraction_page() -> String:
	var file: FileAccess = FileAccess.open(SUCCESS_PAGE_PATH, FileAccess.READ)
	if file:
		var content: String = file.get_as_text()
		file.close()
		return content
	else:
		push_error("Failed to load OAuth success page: %s" % SUCCESS_PAGE_PATH)
		return "<html><body><h1>Error: success.html not found</h1></body></html>"


## Loads and returns the OAuth error page HTML.
func _create_error_page(error: String, description: String) -> String:
	var file: FileAccess = FileAccess.open(ERROR_PAGE_PATH, FileAccess.READ)
	if file:
		var content: String = file.get_as_text()
		file.close()
		return content
	else:
		push_error("Failed to load OAuth error page: %s" % ERROR_PAGE_PATH)
		return "<html><body><h1>Error: error.html not found</h1></body></html>"
