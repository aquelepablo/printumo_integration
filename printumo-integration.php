<?php
/**
 * Plugin Name: Printumo Integration
 * Description: Handles WooCommerce order status changes to send orders to Printumo API, and provides tools to fetch Printumo data.
 * Version: 1.5.0
 * Author: Pablo Nunes Alves
 * Author URI: https://seusite.com
 * License: GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain: printumo-integration
 * Domain Path: /languages
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// ====================================================================
// BASIC API CONFIGURATION (URLs)
// ====================================================================

// Base URL for the Printumo API
define( 'PRINTUMO_BASE_API_URL', 'https://printumo.com/api/v1' );

// URL for Printumo order creation endpoint
define( 'PRINTUMO_ORDERS_API_URL', PRINTUMO_BASE_API_URL . '/orders' );

// URL for Printumo products endpoint
define( 'PRINTUMO_PRODUCTS_API_URL', PRINTUMO_BASE_API_URL . '/products' );

// URL for Printumo shipping profiles endpoint
define( 'PRINTUMO_SHIPPING_PROFILES_API_URL', PRINTUMO_BASE_API_URL . '/shipping_profiles' );

// ====================================================================
// PLUGIN ACTIVATION - ERROR LOG TABLE CREATION
// ====================================================================

/**
 * Creates the custom database table for error logs upon plugin activation.
 */
function printumo_activate_plugin() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'printumo_error_logs';

    $charset_collate = $wpdb->get_charset_collate();

    // SQL to create the table
    $sql = "CREATE TABLE $table_name (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        timestamp datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
        type varchar(50) NOT NULL,
        message text NOT NULL,
        details longtext,
        PRIMARY KEY (id)
    ) $charset_collate;";

    // Include upgrade.php for dbDelta()
    require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
    dbDelta( $sql );
}
register_activation_hook( __FILE__, 'printumo_activate_plugin' );

// ====================================================================
// FUNCTION TO LOG ERRORS TO THE DATABASE
// ====================================================================

/**
 * Logs an error message to the custom database table.
 *
 * @param string $type    Type of error (e.g., 'webhook', 'api_product', 'api_shipping').
 * @param string $message A brief message describing the error.
 * @param array  $details Optional: An array of additional details to store (e.g., payload, response).
 */
function printumo_log_error( $type, $message, $details = array() ) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'printumo_error_logs';

    $wpdb->insert(
        $table_name,
        array(
            'timestamp' => current_time( 'mysql' ),
            'type'      => sanitize_text_field( $type ),
            'message'   => sanitize_textarea_field( $message ),
            'details'   => wp_json_encode( $details ), // Store details as JSON
        ),
        array( '%s', '%s', '%s', '%s' )
    );
}


// ====================================================================
// REGISTER REST ENDPOINTS FOR WEBHOOKS AND TOOLS
// ====================================================================

/**
 * Registers custom REST API endpoints for WooCommerce webhooks and Printumo data fetching.
 */
function printumo_register_api_endpoints() {
    // Endpoint to receive WooCommerce order status update webhook
    register_rest_route( 'printumo/v1', '/webhook', array(
        'methods'             => 'POST',
        'callback'            => 'printumo_handle_webhook_data',
        // IMPORTANT: For production, implement robust permission_callback (e.g., shared secret verification).
        // For simplicity, we allow all requests here, but this is a security risk.
        'permission_callback' => '__return_true',
    ));

    // Permission callback for admin-only endpoints with nonce verification
    $admin_permission_callback = function( WP_REST_Request $request ) {
        error_log( '--- Printumo REST API Permission Check Start ---' );

        // Log relevant $_SERVER variables
        error_log( 'Printumo REST API Permission Check: $_SERVER[HTTP_HOST]: ' . ( isset( $_SERVER['HTTP_HOST'] ) ? $_SERVER['HTTP_HOST'] : 'N/A' ) );
        error_log( 'Printumo REST API Permission Check: $_SERVER[SERVER_NAME]: ' . ( isset( $_SERVER['SERVER_NAME'] ) ? $_SERVER['SERVER_NAME'] : 'N/A' ) );
        error_log( 'Printumo REST API Permission Check: $_SERVER[REQUEST_URI]: ' . ( isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : 'N/A' ) );
        error_log( 'Printumo REST API Permission Check: $_SERVER[SCRIPT_NAME]: ' . ( isset( $_SERVER['SCRIPT_NAME'] ) ? $_SERVER['SCRIPT_NAME'] : 'N/A' ) );
        error_log( 'Printumo REST API Permission Check: $_SERVER[PHP_SELF]: ' . ( isset( $_SERVER['PHP_SELF'] ) ? $_SERVER['PHP_SELF'] : 'N/A' ) );
        error_log( 'Printumo REST API Permission Check: $_SERVER[HTTPS]: ' . ( isset( $_SERVER['HTTPS'] ) ? $_SERVER['HTTPS'] : 'N/A' ) );
        error_log( 'Printumo REST API Permission Check: $_SERVER[SERVER_PORT]: ' . ( isset( $_SERVER['SERVER_PORT'] ) ? $_SERVER['SERVER_PORT'] : 'N/A' ) );
        error_log( 'Printumo REST API Permission Check: get_option(siteurl): ' . get_option( 'siteurl' ) );
        error_log( 'Printumo REST API Permission Check: get_option(home): ' . get_option( 'home' ) );


        // Log all cookies received
        error_log( 'Printumo REST API Permission Check: Received Cookies: ' . print_r( $_COOKIE, true ) );

        // Check if user is logged in using WordPress's internal function (before potential manual set)
        $is_logged_in_before = is_user_logged_in();
        error_log( 'Printumo REST API Permission Check: is_user_logged_in() BEFORE potential manual set: ' . ( $is_logged_in_before ? 'Yes' : 'No' ) );

        // Get the current user object (before potential manual set)
        $user_before = wp_get_current_user();
        error_log( 'Printumo REST API Permission Check: User ID from wp_get_current_user() BEFORE potential manual set: ' . ( $user_before ? $user_before->ID : 'N/A' ) . ' | User Exists: ' . ( $user_before && $user_before->exists() ? 'Yes' : 'No' ) );

        // Validate authentication cookie explicitly
        $auth_cookie = '';
        $auth_cookie_name = '';
        foreach ( $_COOKIE as $name => $value ) {
            if ( strpos( $name, 'wordpress_logged_in_' ) === 0 ) {
                $auth_cookie_name = $name;
                $auth_cookie = $value;
                break;
            }
        }
        $valid_auth_cookie_user_id = wp_validate_auth_cookie( $auth_cookie, 'logged_in' );
        error_log( 'Printumo REST API Permission Check: Auth Cookie Name: ' . ( $auth_cookie_name ? $auth_cookie_name : 'N/A' ) );
        error_log( 'Printumo REST API Permission Check: wp_validate_auth_cookie result (User ID): ' . ( $valid_auth_cookie_user_id ? $valid_auth_cookie_user_id : 'Invalid/Missing' ) );

        // --- Core Fix for Authentication Discrepancy ---
        // If wp_validate_auth_cookie returns a valid user ID, but wp_get_current_user() doesn't
        // recognize the user, it means the global user state hasn't been set for this request.
        // We need to manually set it.
        if ( $valid_auth_cookie_user_id && ( ! $user_before || ! $user_before->exists() || $user_before->ID != $valid_auth_cookie_user_id ) ) {
            error_log( 'Printumo REST API Permission Check: Manually setting current user based on valid auth cookie: User ID ' . $valid_auth_cookie_user_id );
            wp_set_current_user( $valid_auth_cookie_user_id );
            // Note: wp_set_auth_cookie is not needed here as the cookie is already sent by the browser.
            // wp_set_current_user is enough to set the global $current_user for this request.

            // Re-get the user and logged in status after setting
            $user = wp_get_current_user();
            $is_logged_in = is_user_logged_in();
            error_log( 'Printumo REST API Permission Check: is_user_logged_in() AFTER manual set: ' . ( $is_logged_in ? 'Yes' : 'No' ) );
            error_log( 'Printumo REST API Permission Check: User ID from wp_get_current_user() AFTER manual set: ' . ( $user ? $user->ID : 'N/A' ) . ' | User Exists: ' . ( $user && $user->exists() ? 'Yes' : 'No' ) );
        } else {
            // If no manual set was needed, use the initial user object
            $user = $user_before;
            $is_logged_in = $is_logged_in_before;
        }
        // --- End Core Fix ---


        // 1. Check if user is logged in and exists (using the potentially updated $user object)
        if ( ! $user || ! $user->exists() || ! $is_logged_in ) {
            $user_id_for_log = $user ? $user->ID : 'N/A'; // Capture user ID even if not existing
            error_log( 'Printumo REST API Permission Check: Final check: User not logged in or does not exist. Returning 401. User ID seen: ' . $user_id_for_log );
            printumo_log_error(
                'rest_auth_error',
                __( 'User not logged in to access admin endpoint.', 'printumo-integration' ),
                array(
                    'user_id'           => $user_id_for_log,
                    'endpoint'          => $request->get_route(),
                    'is_logged_in_func' => $is_logged_in,
                    'auth_cookie_valid' => $valid_auth_cookie_user_id,
                    'cookies_received'  => $_COOKIE, // Log all cookies for debugging
                    'server_vars'       => array(
                        'HTTP_HOST'   => isset( $_SERVER['HTTP_HOST'] ) ? $_SERVER['HTTP_HOST'] : 'N/A',
                        'SERVER_NAME' => isset( $_SERVER['SERVER_NAME'] ) ? $_SERVER['SERVER_NAME'] : 'N/A',
                        'REQUEST_URI' => isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : 'N/A',
                        'HTTPS'       => isset( $_SERVER['HTTPS'] ) ? $_SERVER['HTTPS'] : 'N/A',
                        'SERVER_PORT' => isset( $_SERVER['SERVER_PORT'] ) ? $_SERVER['SERVER_PORT'] : 'N/A',
                    ),
                    'wp_urls'           => array(
                        'siteurl' => get_option( 'siteurl' ),
                        'home'    => get_option( 'home' ),
                    ),
                )
            );
            error_log( '--- Printumo REST API Permission Check End (401) ---' );
            return new WP_Error(
                'rest_not_logged_in',
                __( 'You must be logged in to access this endpoint.', 'printumo-integration' ),
                array( 'status' => 401 ) // 401 Unauthorized
            );
        }

        error_log( 'Printumo REST API Permission Check: User capabilities: ' . print_r( $user->allcaps, true ) );

        // 2. Check user capability
        if ( ! $user->has_cap( 'manage_options' ) ) { // Use has_cap() on the user object
            error_log( 'Printumo REST API Permission Check: User does not have manage_options capability. Returning 403.' );
            printumo_log_error(
                'rest_permission_error',
                __( 'User lacks required capability for admin endpoint.', 'printumo-integration' ),
                array( 'user_id' => $user->ID, 'endpoint' => $request->get_route(), 'capabilities' => $user->allcaps )
            );
            error_log( '--- Printumo REST API Permission Check End (403 - Capability) ---' );
            return new WP_Error(
                'rest_forbidden_capability',
                __( 'You do not have sufficient permissions to access this endpoint.', 'printumo-integration' ),
                array( 'status' => 403 ) // 403 Forbidden
            );
        }

        // 3. Get and verify nonce
        $nonce = $request->get_param( 'nonce' ); // Get nonce from query parameter
        error_log( 'Printumo REST API Permission Check: Nonce received: ' . ( $nonce ? 'Yes' : 'No' ) . ' | Nonce value: ' . ( $nonce ? $nonce : 'N/A' ) );

        if ( ! wp_verify_nonce( $nonce, 'wp_rest' ) ) {
            error_log( 'Printumo REST API Permission Check: Invalid nonce. Returning 403.' );
            printumo_log_error(
                'rest_nonce_error',
                __( 'Invalid nonce for admin endpoint.', 'printumo-integration' ),
                array( 'user_id' => $user->ID, 'endpoint' => $request->get_route(), 'nonce_value' => $nonce )
            );
            error_log( '--- Printumo REST API Permission Check End (403 - Nonce) ---' );
            return new WP_Error(
                'rest_nonce_invalid',
                __( 'Invalid nonce.', 'printumo-integration' ),
                array( 'status' => 403 ) // 403 Forbidden for invalid nonce
            );
        }

        error_log( 'Printumo REST API Permission Check: All permission checks passed. Access granted.' );
        error_log( '--- Printumo REST API Permission Check End (Success) ---' );
        return true; // If all checks pass
    };

    // Endpoint to fetch products from Printumo (triggered via admin)
    register_rest_route( 'printumo/v1', '/fetch-products', array(
        'methods'             => 'GET',
        'callback'            => 'printumo_fetch_products_from_api',
        'permission_callback' => $admin_permission_callback, // Use the new combined permission callback
        'args'                => array(
            // Nonce is now handled directly in permission_callback, no need to define here as required param
        ),
    ));

    // Endpoint to fetch shipping profiles from Printumo (triggered via admin)
    register_rest_route( 'printumo/v1', '/fetch-shipping-profiles', array(
        'methods'             => 'GET',
        'callback'            => 'printumo_fetch_shipping_profiles_from_api',
        'permission_callback' => $admin_permission_callback, // Use the new combined permission callback
        'args'                => array(
            // Nonce is now handled directly in permission_callback, no need to define here as required param
        ),
    ));

    // NEW: Endpoint to sync shipping data to WooCommerce
    register_rest_route( 'printumo/v1', '/sync-shipping-data', array(
        'methods'             => 'POST', // Use POST as it modifies data
        'callback'            => 'printumo_sync_shipping_data_to_woocommerce',
        'permission_callback' => $admin_permission_callback,
        'args'                => array(
            // No specific args expected in the request body for now, as it fetches data internally
        ),
    ));
}
add_action( 'rest_api_init', 'printumo_register_api_endpoints' );

// ====================================================================
// FUNCTION TO HANDLE WEBHOOK DATA (ORDER CREATION)
// ====================================================================

/**
 * Handles the incoming webhook data from WooCommerce.
 * This function processes the order, checks its status, and sends it to Printumo if applicable.
 *
 * @param WP_REST_Request $request The REST API request object.
 * @return WP_REST_Response A response indicating success or failure.
 */
function printumo_handle_webhook_data( WP_REST_Request $request ) {
    $payload = $request->get_json_params();

    // Retrieve API Key and trigger status from plugin options
    $printumo_api_key = get_option( 'printumo_api_key' );
    $trigger_status = get_option( 'printumo_order_trigger_status', 'pronto-para-printumo' ); // Default if not set

    if ( empty( $printumo_api_key ) ) {
        $message = 'Printumo API Key is not configured in plugin settings.';
        error_log( 'Printumo Webhook Error: ' . $message );
        printumo_log_error( 'config_error', $message );
        return new WP_REST_Response( array( 'success' => false, 'message' => $message ), 500 );
    }

    // Log the full payload for debugging purposes.
    error_log( 'Printumo Webhook Received: ' . print_r( $payload, true ) );

    // Check if essential order data is present in the payload.
    if ( ! isset( $payload['order'] ) || ! isset( $payload['order']['status'] ) ) {
        $message = 'Missing order data or status in payload.';
        error_log( 'Printumo Webhook Error: ' . $message );
        printumo_log_error( 'webhook_data_error', $message, array( 'payload' => $payload ) );
        return new WP_REST_Response( array( 'success' => false, 'message' => $message ), 400 );
    }

    $order_data = $payload['order'];
    $order_id = isset( $order_data['id'] ) ? $order_data['id'] : 'N/A';
    $new_status = $order_data['status'];

    // Check if the new order status matches the one configured for Printumo integration.
    // WooCommerce webhook status format is 'wc-status_slug', so we need to prepend 'wc-'
    if ( 'wc-' . $new_status !== $trigger_status ) {
        error_log( "Printumo Webhook: Order {$order_id} status '{$new_status}' is not the target status ('" . str_replace('wc-', '', $trigger_status) . "'). No action taken." );
        return new WP_REST_Response( array( 'success' => true, 'message' => 'Order status not relevant for Printumo integration.' ), 200 );
    }

    // Extract necessary order details for Printumo.
    $line_items_woo = $order_data['line_items'];
    $shipping_address_woo = $order_data['shipping_address'];
    $currency = $order_data['currency'];

    $printumo_line_items = array();
    foreach ( $line_items_woo as $item ) {
        $product_id_woo = $item['product_id'];
        $quantity = $item['quantity'];

        // CRITICAL: Product mapping from WooCommerce Product ID to Printumo Variant ID.
        // We assume the Printumo Variant ID is stored as a custom field '_printumo_variant_id'
        // on the WooCommerce product.
        $printumo_variant_id = get_post_meta( $product_id_woo, '_printumo_variant_id', true );

        if ( empty( $printumo_variant_id ) ) {
            $message = "WooCommerce Product ID {$product_id_woo} (from Order {$order_id}) has no Printumo variant ID mapped. This item will be skipped.";
            error_log( "Printumo Webhook Error: " . $message );
            printumo_log_error( 'product_mapping_error', $message, array( 'order_id' => $order_id, 'product_id_woo' => $product_id_woo ) );
            // You can choose to skip this item or return an error for the entire order.
            continue;
        }

        $printumo_line_items[] = array(
            'variant_id' => (int) $printumo_variant_id,
            'quantity'   => (int) $quantity,
        );
    }

    // If no valid line items were found after mapping, do not send the order.
    if ( empty( $printumo_line_items ) ) {
        $message = "No valid line items with Printumo Variant IDs found for Order {$order_id}. Order not sent.";
        error_log( "Printumo Webhook Error: " . $message );
        printumo_log_error( 'empty_line_items', $message, array( 'order_id' => $order_id ) );
        return new WP_REST_Response( array( 'success' => false, 'message' => $message ), 400 );
    }

    // Prepare the shipping address in Printumo's required format.
    $printumo_shipping_address = array(
        'email'        => $shipping_address_woo['email'],
        'first_name'   => $shipping_address_woo['first_name'],
        'last_name'    => $shipping_address_woo['last_name'],
        'address1'     => $shipping_address_woo['address_1'], // WooCommerce uses 'address_1'
        'city'         => $shipping_address_woo['city'],
        'postcode'     => $shipping_address_woo['postcode'],
        'country_code' => $shipping_address_woo['country'], // WooCommerce uses 'country' (ISO 2-letter code)
    );

    // Construct the final payload for the Printumo API.
    $printumo_payload = array(
        'line_items'       => $printumo_line_items,
        'shipping_address' => $printumo_shipping_address,
        'selected_currency' => $currency,
    );

    // Send the request to the Printumo API.
    $response = wp_remote_post( PRINTUMO_ORDERS_API_URL, array(
        'headers' => array(
            'Content-Type'  => 'application/json',
            'Authorization' => 'Bearer ' . $printumo_api_key, // Use configured API Key
        ),
        'body'    => json_encode( $printumo_payload ),
        'timeout' => 45, // Set a reasonable timeout for the API call.
    ));

    // Handle the response from the Printumo API.
    if ( is_wp_error( $response ) ) {
        $error_message = $response->get_error_message();
        error_log( "Printumo API Connection Error for Order {$order_id}: " . $error_message );
        printumo_log_error( 'api_connection_error', "Failed to connect to Printumo API for Order {$order_id}: " . $error_message, array( 'order_id' => $order_id, 'payload' => $printumo_payload ) );
        return new WP_REST_Response( array( 'success' => false, 'message' => 'Failed to connect to Printumo API: ' . $error_message ), 500 );
    }

    $body = wp_remote_retrieve_body( $response );
    $data = json_decode( $body, true );
    $status_code = wp_remote_retrieve_response_code( $response );

    if ( $status_code === 201 && isset( $data['success'] ) && $data['success'] === true ) {
        // API call was successful.
        $printumo_order_id = isset( $data['data']['order_id'] ) ? $data['data']['order_id'] : 'N/A';
        error_log( "Printumo API Success for Order {$order_id}: Printumo Order ID {$printumo_order_id}." );

        // OPTIONAL: Store the Printumo Order ID in the WooCommerce order meta for reference.
        update_post_meta( $order_id, '_printumo_order_id', $printumo_order_id );

        return new WP_REST_Response( array( 'success' => true, 'message' => 'Order sent to Printumo successfully.', 'printumo_order_id' => $printumo_order_id ), 200 );
    } else {
        // Printumo API returned an error.
        $error_details = isset( $data['error'] ) ? $data['error'] : 'Unknown error';
        $errors_array = isset( $data['errors'] ) ? implode( ', ', $data['errors'] ) : '';
        $message = "Printumo API Failure for Order {$order_id} (Status: {$status_code}): {$error_details} - {$errors_array}";
        error_log( $message );
        printumo_log_error( 'api_response_error', $message, array( 'order_id' => $order_id, 'status_code' => $status_code, 'response_body' => $body, 'payload' => $printumo_payload ) );
        return new WP_REST_Response( array( 'success' => false, 'message' => 'Printumo API error: ' . $error_details . ' ' . $errors_array ), $status_code );
    }
}

// ====================================================================
// FUNCTIONS TO FETCH DATA FROM PRINTUMO (PRODUCTS AND SHIPPING PROFILES)
// ====================================================================

/**
 * Fetches products from the Printumo API.
 *
 * @param WP_REST_Request $request The REST API request object (not used for this simple GET).
 * @return WP_REST_Response A response containing the fetched products or an error.
 */
function printumo_fetch_products_from_api( WP_REST_Request $request ) {
    $printumo_api_key = get_option( 'printumo_api_key' );
    if ( empty( $printumo_api_key ) ) {
        $message = 'Printumo API Key is not configured in plugin settings.';
        printumo_log_error( 'config_error', $message );
        return new WP_REST_Response( array( 'success' => false, 'message' => $message ), 500 );
    }

    $response = wp_remote_get( PRINTUMO_PRODUCTS_API_URL, array(
        'headers' => array(
            'Authorization' => 'Bearer ' . $printumo_api_key, // Use configured API Key
        ),
        'timeout' => 45,
    ));

    if ( is_wp_error( $response ) ) {
        $error_message = $response->get_error_message();
        error_log( "Printumo API Connection Error (Products): " . $error_message );
        printumo_log_error( 'api_connection_error', "Failed to connect to Printumo API (Products): " . $error_message, array( 'endpoint' => 'products' ) );
        return new WP_REST_Response( array( 'success' => false, 'message' => 'Failed to connect to Printumo API (Products): ' . $error_message ), 500 );
    }

    $body = wp_remote_retrieve_body( $response );
    $data = json_decode( $body, true );
    $status_code = wp_remote_retrieve_response_code( $response );

    if ( $status_code === 200 && isset( $data['success'] ) && $data['success'] === true ) {
        error_log( "Printumo API Success (Products): " . count($data['data']) . " products fetched." );
        return new WP_REST_Response( array( 'success' => true, 'data' => $data['data'] ), 200 );
    } else {
        $error_details = isset( $data['error'] ) ? $data['error'] : 'Unknown error';
        $errors_array = isset( $data['errors'] ) ? implode( ', ', $data['errors'] ) : '';
        $message = "Printumo API Failure (Products) (Status: {$status_code}): {$error_details} - {$errors_array}";
        error_log( $message );
        printumo_log_error( 'api_response_error', $message, array( 'endpoint' => 'products', 'status_code' => $status_code, 'response_body' => $body ) );
        return new WP_REST_Response( array( 'success' => false, 'message' => 'Printumo API error (Products): ' . $error_details . ' ' . $errors_array ), $status_code );
    }
}

/**
 * Fetches shipping profiles from the Printumo API.
 *
 * @param WP_REST_Request $request The REST API request object (not used for this simple GET).
 * @return WP_REST_Response A response containing the fetched shipping profiles or an error.
 */
function printumo_fetch_shipping_profiles_from_api( WP_REST_Request $request ) {
    $printumo_api_key = get_option( 'printumo_api_key' );
    if ( empty( $printumo_api_key ) ) {
        $message = 'Printumo API Key is not configured in plugin settings.';
        printumo_log_error( 'config_error', $message );
        return new WP_REST_Response( array( 'success' => false, 'message' => $message ), 500 );
    }

    $response = wp_remote_get( PRINTUMO_SHIPPING_PROFILES_API_URL, array(
        'headers' => array(
            'Authorization' => 'Bearer ' . $printumo_api_key, // Use configured API Key
        ),
        'timeout' => 45,
    ));

    if ( is_wp_error( $response ) ) {
        $error_message = $response->get_error_message();
        error_log( "Printumo API Connection Error (Shipping Profiles): " . $error_message );
        printumo_log_error( 'api_connection_error', "Failed to connect to Printumo API (Shipping Profiles): " . $error_message, array( 'endpoint' => 'shipping_profiles' ) );
        return new WP_REST_Response( array( 'success' => false, 'message' => 'Failed to connect to Printumo API (Shipping Profiles): ' . $error_message ), 500 );
    }

    $body = wp_remote_retrieve_body( $response );
    $data = json_decode( $body, true );
    $status_code = wp_remote_retrieve_response_code( $response );

    if ( $status_code === 200 && isset( $data['success'] ) && $data['success'] === true ) {
        error_log( "Printumo API Success (Shipping Profiles): " . count($data['data']) . " profiles fetched." );
        return new WP_REST_Response( array( 'success' => true, 'data' => $data['data'] ), 200 );
    } else {
        $error_details = isset( $data['error'] ) ? $data['error'] : 'Unknown error';
        $errors_array = isset( $data['errors'] ) ? implode( ', ', $data['errors'] ) : '';
        $message = "Printumo API Failure (Shipping Profiles) (Status: {$status_code}): {$error_details} - {$errors_array}";
        error_log( $message );
        printumo_log_error( 'api_response_error', $message, array( 'endpoint' => 'shipping_profiles', 'status_code' => $status_code, 'response_body' => $body ) );
        return new WP_REST_Response( array( 'success' => false, 'message' => 'Printumo API error (Shipping Profiles): ' . $error_details . ' ' . $errors_array ), $status_code );
    }
}

// ====================================================================
// NEW: FUNCTION TO SYNC SHIPPING DATA TO WOOCOMMERCE
// ====================================================================

/**
 * Syncs shipping profiles from Printumo to WooCommerce as Shipping Zones and Shipping Classes.
 *
 * @param WP_REST_Request $request The REST API request object.
 * @return WP_REST_Response A response indicating success or failure of the sync.
 */
function printumo_sync_shipping_data_to_woocommerce( WP_REST_Request $request ) {
    // Ensure WooCommerce is active
    if ( ! class_exists( 'WooCommerce' ) ) {
        $message = 'WooCommerce is not active. Shipping sync requires WooCommerce.';
        printumo_log_error( 'woocommerce_not_active', $message );
        return new WP_REST_Response( array( 'success' => false, 'message' => $message ), 400 );
    }

    // Fetch latest shipping profiles from Printumo
    $response = printumo_fetch_shipping_profiles_from_api( $request ); // Re-use the existing fetch function
    $response_data = $response->get_data();

    if ( ! $response_data['success'] ) {
        $message = 'Failed to fetch shipping profiles from Printumo: ' . $response_data['message'];
        printumo_log_error( 'sync_fetch_error', $message, $response_data );
        return new WP_REST_Response( array( 'success' => false, 'message' => $message ), 500 );
    }

    $printumo_profiles = $response_data['data'];
    $sync_results = array(
        'zones_created_updated'  => 0,
        'classes_created_updated' => 0,
        'errors'                 => array(),
    );

    // --- Process Shipping Zones ---
    $wc_shipping_zones = WC_Shipping_Zones::get_zones();
    $existing_wc_zone_names = array_column( $wc_shipping_zones, 'zone_name', 'zone_id' );
    $existing_wc_zone_slugs = array(); // To map Printumo market slug to WC zone ID
    foreach ( $wc_shipping_zones as $zone ) {
        $existing_wc_zone_slugs[ sanitize_title( $zone['zone_name'] ) ] = $zone['zone_id'];
    }

    foreach ( $printumo_profiles as $profile ) {
        $market_name = $profile['market']['name'];
        $market_slug = $profile['market']['slug'];
        $market_default_currency = $profile['market']['default_currency'];
        $market_regions = isset( $profile['shipping_costs'][0]['shipping_zone']['regions'] ) ? $profile['shipping_costs'][0]['shipping_zone']['regions'] : array();

        // Try to find an existing zone by slug or name
        $zone_id = false;
        if ( isset( $existing_wc_zone_slugs[ $market_slug ] ) ) {
            $zone_id = $existing_wc_zone_slugs[ $market_slug ];
        } else {
            // Fallback: check by name if slug didn't match (less reliable but good for existing manual zones)
            foreach ( $wc_shipping_zones as $zone_data ) {
                if ( $zone_data['zone_name'] === $market_name ) {
                    $zone_id = $zone_data['zone_id'];
                    break;
                }
            }
        }

        $zone = null;
        if ( $zone_id ) {
            $zone = new WC_Shipping_Zone( $zone_id );
            error_log( "Printumo Sync: Found existing shipping zone: {$market_name} (ID: {$zone_id})" );
        } else {
            // Create new zone
            $zone_args = array(
                'zone_name' => $market_name,
            );
            $zone_id = WC_Shipping_Zones::add_zone( $zone_args );
            if ( $zone_id ) {
                $zone = new WC_Shipping_Zone( $zone_id );
                error_log( "Printumo Sync: Created new shipping zone: {$market_name} (ID: {$zone_id})" );
                $sync_results['zones_created_updated']++;
            } else {
                $sync_results['errors'][] = "Failed to create shipping zone for market: {$market_name}";
                printumo_log_error( 'shipping_zone_creation_error', "Failed to create shipping zone: {$market_name}", array( 'market_data' => $profile['market'] ) );
                continue; // Skip to next profile if zone creation failed
            }
        }

        // Update zone locations (countries/provinces)
        $zone_locations = array();
        foreach ( $market_regions as $region ) {
            // WooCommerce expects 'country_code:province_code' for provinces, or 'country_code' for countries
            if ( ! empty( $region['province_code'] ) ) {
                $zone_locations[] = array(
                    'code' => $region['country_code'] . ':' . $region['province_code'],
                    'type' => 'state',
                );
            } else {
                $zone_locations[] = array(
                    'code' => $region['country_code'],
                    'type' => 'country',
                );
            }
        }
        // Remove existing locations first to prevent duplicates or stale data
        $zone->delete_zone_locations();
        foreach ( $zone_locations as $location ) {
            $zone->add_location( $location['code'], $location['type'] );
        }
        error_log( "Printumo Sync: Updated locations for zone {$market_name} (ID: {$zone_id})" );


        // --- Add/Update Flat Rate Shipping Method ---
        $flat_rate_method_id = 'flat_rate'; // Standard WooCommerce Flat Rate method ID
        $methods = $zone->get_shipping_methods();
        $flat_rate_exists = false;
        foreach ( $methods as $method ) {
            if ( $method->id === $flat_rate_method_id ) {
                $flat_rate_exists = true;
                // Update existing Flat Rate method
                $method->set_option( 'title', __( 'Printumo Flat Rate', 'printumo-integration' ) );
                $method->set_option( 'tax_status', 'taxable' ); // Or 'none' based on your preference
                // Set a base cost. For now, we'll use the first shipping cost found for this profile.
                // A more advanced mapping for additional_unit_price would go here.
                $base_cost = 0;
                if ( isset( $profile['shipping_costs'][0]['price']['amount'] ) ) {
                    $base_cost = wc_format_decimal( $profile['shipping_costs'][0]['price']['amount'] / 100, 2 ); // Convert cents to dollars/euros
                }
                $method->set_option( 'cost', $base_cost );
                $method->save();
                error_log( "Printumo Sync: Updated Flat Rate method for zone {$market_name} (ID: {$zone_id}) with base cost: {$base_cost} {$market_default_currency}" );
                break;
            }
        }

        if ( ! $flat_rate_exists ) {
            // Add new Flat Rate method
            $instance_id = $zone->add_shipping_method( $flat_rate_method_id );
            if ( $instance_id ) {
                $new_method = $zone->get_shipping_method( $instance_id );
                $new_method->set_option( 'title', __( 'Printumo Flat Rate', 'printumo-integration' ) );
                $new_method->set_option( 'tax_status', 'taxable' );
                $base_cost = 0;
                if ( isset( $profile['shipping_costs'][0]['price']['amount'] ) ) {
                    $base_cost = wc_format_decimal( $profile['shipping_costs'][0]['price']['amount'] / 100, 2 );
                }
                $new_method->set_option( 'cost', $base_cost );
                $new_method->save();
                error_log( "Printumo Sync: Added new Flat Rate method for zone {$market_name} (ID: {$zone_id}) with base cost: {$base_cost} {$market_default_currency}" );
            } else {
                $sync_results['errors'][] = "Failed to add Flat Rate method to zone: {$market_name}";
                printumo_log_error( 'shipping_method_creation_error', "Failed to add Flat Rate method to zone: {$market_name}", array( 'zone_id' => $zone_id ) );
            }
        }
    }

    // --- Process Shipping Classes ---
    $existing_wc_shipping_classes = WC_Shipping_Classes::get_shipping_classes();
    $existing_wc_class_slugs = array_column( $existing_wc_shipping_classes, 'slug', 'term_id' );
    $existing_wc_class_names = array_column( $existing_wc_shipping_classes, 'name', 'term_id' );

    $unique_printumo_shipping_classes = array(); // Stores unique combinations of print_type and size
    foreach ( $printumo_profiles as $profile ) {
        $print_type_name = $profile['print_type']['name'];
        foreach ( $profile['sizes'] as $size ) {
            $size_name = $size['name'];
            $class_name = $print_type_name . ' - ' . $size_name;
            $class_slug = sanitize_title( $class_name );
            $unique_printumo_shipping_classes[ $class_slug ] = $class_name;
        }
    }

    foreach ( $unique_printumo_shipping_classes as $slug => $name ) {
        $class_id = false;
        // Check if class exists by slug
        if ( in_array( $slug, $existing_wc_class_slugs ) ) {
            $class_id = array_search( $slug, $existing_wc_class_slugs );
            error_log( "Printumo Sync: Found existing shipping class: {$name} (ID: {$class_id})" );
        } else {
            // Check if class exists by name (less reliable but good for existing manual classes)
            foreach( $existing_wc_shipping_classes as $class_data ) {
                if ( $class_data->name === $name ) {
                    $class_id = $class_data->term_id;
                    break;
                }
            }
        }

        if ( ! $class_id ) {
            // Create new shipping class
            $new_class_id = wp_insert_term(
                $name, // The class name
                'product_shipping_class', // Taxonomy
                array(
                    'description' => sprintf( __( 'Printumo shipping class for %s.', 'printumo-integration' ), $name ),
                    'slug'        => $slug,
                )
            );

            if ( ! is_wp_error( $new_class_id ) ) {
                error_log( "Printumo Sync: Created new shipping class: {$name} (ID: {$new_class_id['term_id']})" );
                $sync_results['classes_created_updated']++;
            } else {
                $sync_results['errors'][] = "Failed to create shipping class: {$name} - " . $new_class_id->get_error_message();
                printumo_log_error( 'shipping_class_creation_error', "Failed to create shipping class: {$name}", array( 'class_name' => $name, 'error' => $new_class_id->get_error_message() ) );
            }
        }
    }

    $message = sprintf(
        __( 'Shipping sync complete. Zones created/updated: %d. Classes created/updated: %d.', 'printumo-integration' ),
        $sync_results['zones_created_updated'],
        $sync_results['classes_created_updated']
    );

    if ( ! empty( $sync_results['errors'] ) ) {
        $message .= ' ' . __( 'Some errors occurred. Check the error log for details.', 'printumo-integration' );
        return new WP_REST_Response( array( 'success' => false, 'message' => $message, 'details' => $sync_results ), 500 );
    }

    return new WP_REST_Response( array( 'success' => true, 'message' => $message, 'details' => $sync_results ), 200 );
}


// ====================================================================
// ADDITIONAL FUNCTIONALITY (OPTIONAL, BUT HIGHLY RECOMMENDED)
// ====================================================================

/**
 * Adds a custom field to the WooCommerce product data meta box to store the Printumo Variant ID.
 * This makes it easy to map your WooCommerce products to Printumo variants.
 */
function printumo_add_product_variant_id_field() {
    echo '<div class="options_group">';
    woocommerce_wp_text_input(
        array(
            'id'          => '_printumo_variant_id',
            'label'       => __( 'Printumo Variant ID', 'printumo-integration' ),
            'placeholder' => 'Enter Printumo Variant ID',
            'desc_tip'    => 'true',
            'description' => __( 'The unique ID for this product variant in Printumo. This is crucial for sending orders.', 'printumo-integration' ),
            'data_type'   => 'integer',
        )
    );
    echo '</div>';
}
add_action( 'woocommerce_product_options_general_product_data', 'printumo_add_product_variant_id_field' );

/**
 * Saves the custom Printumo Variant ID field when a product is saved.
 */
function printumo_save_product_variant_id_field( $post_id ) {
    $printumo_variant_id = isset( $_POST['_printumo_variant_id'] ) ? sanitize_text_field( $_POST['_printumo_variant_id'] ) : '';
    update_post_meta( $post_id, '_printumo_variant_id', $printumo_variant_id );
}
add_action( 'woocommerce_process_product_meta', 'printumo_save_product_variant_id_field' );

/**
 * OPTIONAL: Registers a custom WooCommerce order status.
 * Uncomment this section if you want to use a custom status like 'Pronto para Printumo'.
 * Remember to update the WOOCOMMERCE_ORDER_STATUS_FOR_PRINTUMO constant above to 'wc-pronto-para-printumo'.
 */
/*
function printumo_register_custom_order_status() {
    register_post_status( 'wc-pronto-para-printumo', array(
        'label'                     => _x( 'Pronto para Printumo', 'Order status', 'printumo-integration' ),
        'public'                    => true,
        'exclude_from_search'       => false,
        'show_in_admin_all_list'    => true,
        'show_in_admin_status_list' => true,
        'label_count'               => _n_noop( 'Pronto para Printumo (%s)', 'Pronto para Printumo (%s)', 'printumo-integration' )
    ) );
}
add_action( 'init', 'printumo_register_custom_order_status' );

// Add the custom status to the WooCommerce order statuses list.
function printumo_add_custom_order_status_to_list( $order_statuses ) {
    $new_order_statuses = array();
    foreach ( $order_statuses as $key => $status ) {
        $new_order_statuses[ $key ] = $status;
        if ( 'wc-processing' === $key ) { // Insert after 'Processing'
            $new_order_statuses['wc-pronto-para-printumo'] = _x( 'Pronto para Printumo', 'Order status', 'printumo-integration' );
        }
    }
    return $new_order_statuses;
}
add_filter( 'wc_order_statuses', 'printumo_add_custom_order_status_to_list' );
*/

// ====================================================================
// ADMIN PAGE AND PLUGIN SETTINGS
// ====================================================================

/**
 * Adds a new menu item under WooCommerce for Printumo Tools.
 */
function printumo_add_admin_menu_page() {
    add_submenu_page(
        'woocommerce', // Parent slug
        __( 'Printumo Tools & Settings', 'printumo-integration' ), // Page title
        __( 'Printumo Tools', 'printumo-integration' ), // Menu title
        'manage_options', // Capability required
        'printumo-tools', // Menu slug
        'printumo_tools_page_content' // Callback function to display the page content
    );
}
add_action( 'admin_menu', 'printumo_add_admin_menu_page' );

/**
 * Registers the plugin settings.
 */
function printumo_register_settings() {
    // Register the setting for Printumo API Key
    register_setting(
        'printumo_settings_group', // Option group
        'printumo_api_key',        // Option name
        array(
            'type'              => 'string',
            'sanitize_callback' => 'sanitize_text_field',
            'default'           => '',
        )
    );

    // Register the setting for WooCommerce Order Trigger Status
    register_setting(
        'printumo_settings_group', // Option group
        'printumo_order_trigger_status', // Option name
        array(
            'type'              => 'string',
            'sanitize_callback' => 'sanitize_text_field',
            'default'           => 'wc-pronto-para-printumo', // Default value
        )
    );

    // Add a settings section
    add_settings_section(
        'printumo_general_settings_section', // ID of the section
        __( 'General Settings', 'printumo-integration' ), // Title of the section
        'printumo_general_settings_section_callback', // Callback function to render the section description
        'printumo-tools' // Page slug where this section will be displayed
    );

    // Add the API Key field
    add_settings_field(
        'printumo_api_key_field', // ID of the field
        __( 'Printumo API Key', 'printumo-integration' ), // Label of the field
        'printumo_api_key_callback', // Callback function to render the field
        'printumo-tools', // Page slug
        'printumo_general_settings_section' // Section ID
    );

    // Add the Order Status dropdown field
    add_settings_field(
        'printumo_order_trigger_status_field', // ID of the field
        __( 'Trigger Order Status', 'printumo-integration' ), // Label of the field
        'printumo_order_trigger_status_callback', // Callback function to render the field
        'printumo-tools', // Page slug
        'printumo_general_settings_section' // Section ID
    );
}
add_action( 'admin_init', 'printumo_register_settings' );

/**
 * Callback for the general settings section description.
 */
function printumo_general_settings_section_callback() {
    echo '<p>' . esc_html__( 'Configure the main settings for the Printumo integration.', 'printumo-integration' ) . '</p>';
}

/**
 * Callback to render the Printumo API Key field.
 */
function printumo_api_key_callback() {
    $api_key = get_option( 'printumo_api_key' );
    echo '<input type="text" id="printumo_api_key" name="printumo_api_key" value="' . esc_attr( $api_key ) . '" class="regular-text" placeholder="' . esc_attr__( 'Enter your Printumo API Key', 'printumo-integration' ) . '">';
    echo '<p class="description">' . esc_html__( 'Your unique API key from Printumo. Required for all API interactions.', 'printumo-integration' ) . '</p>';
}

/**
 * Callback to render the Order Trigger Status dropdown field.
 */
function printumo_order_trigger_status_callback() {
    $current_status = get_option( 'printumo_order_trigger_status', 'wc-pronto-para-printumo' );
    $order_statuses = wc_get_order_statuses(); // Get all WooCommerce order statuses

    echo '<select id="printumo_order_trigger_status" name="printumo_order_trigger_status">';
    foreach ( $order_statuses as $key => $label ) {
        echo '<option value="' . esc_attr( $key ) . '"' . selected( $current_status, $key, false ) . '>' . esc_html( $label ) . '</option>';
    }
    echo '</select>';
    echo '<p class="description">' . esc_html__( 'Select the WooCommerce order status that will trigger the order submission to Printumo.', 'printumo-integration' ) . '</p>';
}


/**
 * Displays the content of the Printumo Tools admin page.
 */
function printumo_tools_page_content() {
    ?>
    <div class="wrap">
        <h1><?php _e( 'Printumo Integration Tools & Settings', 'printumo-integration' ); ?></h1>
        <p><?php _e( 'Manage your Printumo API settings and use tools to interact with the Printumo API.', 'printumo-integration' ); ?></p>

        <h2 class="nav-tab-wrapper">
            <a href="?page=printumo-tools&tab=settings" class="nav-tab <?php echo ( ! isset( $_GET['tab'] ) || $_GET['tab'] == 'settings' ) ? 'nav-tab-active' : ''; ?>"><?php _e( 'Settings', 'printumo-integration' ); ?></a>
            <a href="?page=printumo-tools&tab=tools" class="nav-tab <?php echo ( isset( $_GET['tab'] ) && $_GET['tab'] == 'tools' ) ? 'nav-tab-active' : ''; ?>"><?php _e( 'Tools', 'printumo-integration' ); ?></a>
            <a href="?page=printumo-tools&tab=shipping-sync" class="nav-tab <?php echo ( isset( $_GET['tab'] ) && $_GET['tab'] == 'shipping-sync' ) ? 'nav-tab-active' : ''; ?>"><?php _e( 'Shipping Sync', 'printumo-integration' ); ?></a>
            <a href="?page=printumo-tools&tab=error-log" class="nav-tab <?php echo ( isset( $_GET['tab'] ) && $_GET['tab'] == 'error-log' ) ? 'nav-tab-active' : ''; ?>"><?php _e( 'Error Log', 'printumo-integration' ); ?></a>
        </h2>

        <?php
        $active_tab = isset( $_GET['tab'] ) ? $_GET['tab'] : 'settings';

        if ( 'settings' == $active_tab ) {
            ?>
            <form method="post" action="options.php">
                <?php
                settings_fields( 'printumo_settings_group' ); // Settings group name
                do_settings_sections( 'printumo-tools' ); // Page slug
                submit_button();
                ?>
            </form>
            <?php
        } elseif ( 'tools' == $active_tab ) {
            ?>
            <hr>

            <h2><?php _e( 'Fetch Products from Printumo', 'printumo-integration' ); ?></h2>
            <p><?php _e( 'Click the button below to retrieve your accepted products from Printumo. This can help you map Printumo Variant IDs to your WooCommerce products.', 'printumo-integration' ); ?></p>
            <button id="printumo-fetch-products" class="button button-primary"><?php _e( 'Fetch Products', 'printumo-integration' ); ?></button>
            <div id="printumo-products-results" style="margin-top: 20px; background-color: #f0f0f0; padding: 15px; border-radius: 5px; max-height: 400px; overflow-y: auto; white-space: pre-wrap; word-wrap: break-word;">
                <?php _e( 'Results will appear here.', 'printumo-integration' ); ?>
            </div>

            <hr>

            <h2><?php _e( 'Fetch Shipping Profiles from Printumo', 'printumo-integration' ); ?></h2>
            <p><?php _e( 'Click the button below to retrieve comprehensive shipping information from Printumo. This can be useful for configuring shipping zones in WooCommerce.', 'printumo-integration' ); ?></p>
            <button id="printumo-fetch-shipping-profiles" class="button button-primary"><?php _e( 'Fetch Shipping Profiles', 'printumo-integration' ); ?></button>
            <div id="printumo-shipping-profiles-results" style="margin-top: 20px; background-color: #f0f0f0; padding: 15px; border-radius: 5px; max-height: 400px; overflow-y: auto; white-space: pre-wrap; word-wrap: break-word;">
                <?php _e( 'Results will appear here.', 'printumo-integration' ); ?>
            </div>

            <script type="text/javascript">
                jQuery(document).ready(function($) {
                    // Generate nonce once
                    var wp_nonce = '<?php echo wp_create_nonce( 'wp_rest' ); ?>';

                    // Add a warning about caching for nonce issues
                    var $nonceWarning = $('<p style="color: red; font-weight: bold;"><?php _e( 'If you encounter "Invalid nonce" errors, please try clearing your website cache and reloading this page.', 'printumo-integration' ); ?></p>');
                    $nonceWarning.insertAfter('h2:contains("Fetch Products from Printumo")'); // Add after the first H2 in Tools tab

                    // Handle Fetch Products button click
                    $('#printumo-fetch-products').on('click', function() {
                        var $button = $(this);
                        var $resultsDiv = $('#printumo-products-results');
                        $resultsDiv.text('<?php _e( 'Fetching products...', 'printumo-integration' ); ?>');
                        $button.prop('disabled', true);

                        $.ajax({
                            url: '<?php echo esc_url_raw( rest_url( 'printumo/v1/fetch-products' ) ); ?>' + '?nonce=' + wp_nonce, // Added nonce to URL
                            method: 'GET',
                            // No need for beforeSend to set X-WP-Nonce header if sent as URL param
                            success: function(response) {
                                if (response.success) {
                                    $resultsDiv.text(JSON.stringify(response.data, null, 2));
                                } else {
                                    $resultsDiv.text('Error: ' + response.message);
                                }
                            },
                            error: function(jqXHR, textStatus, errorThrown) {
                                var errorMessage = 'AJAX Error: ' + textStatus + ' - ' + errorThrown + '\n';
                                if (jqXHR.responseJSON && jqXHR.responseJSON.message) {
                                    errorMessage += 'Server Message: ' + jqXHR.responseJSON.message + '\n';
                                }
                                if (jqXHR.responseText) {
                                    errorMessage += 'Full Response: ' + jqXHR.responseText;
                                }
                                $resultsDiv.text(errorMessage);
                            },
                            complete: function() {
                                $button.prop('disabled', false);
                            }
                        });
                    });

                    // Handle Fetch Shipping Profiles button click
                    $('#printumo-fetch-shipping-profiles').on('click', function() {
                        var $button = $(this);
                        var $resultsDiv = $('#printumo-shipping-profiles-results');
                        $resultsDiv.text('<?php _e( 'Fetching shipping profiles...', 'printumo-integration' ); ?>');
                        $button.prop('disabled', true);

                        $.ajax({
                            url: '<?php echo esc_url_raw( rest_url( 'printumo/v1/fetch-shipping-profiles' ) ); ?>' + '?nonce=' + wp_nonce, // Added nonce to URL
                            method: 'GET',
                            // No need for beforeSend to set X-WP-Nonce header if sent as URL param
                            success: function(response) {
                                if (response.success) {
                                    $resultsDiv.text(JSON.stringify(response.data, null, 2));
                                } else {
                                    $resultsDiv.text('Error: ' + response.message);
                                }
                            },
                            error: function(jqXHR, textStatus, errorThrown) {
                                var errorMessage = 'AJAX Error: ' + textStatus + ' - ' + errorThrown + '\n';
                                if (jqXHR.responseJSON && jqXHR.responseJSON.message) {
                                    errorMessage += 'Server Message: ' + jqXHR.responseJSON.message + '\n';
                                }
                                if (jqXHR.responseText) {
                                    errorMessage += 'Full Response: ' + jqXHR.responseText;
                                }
                                $resultsDiv.text(errorMessage);
                            },
                            complete: function() {
                                $button.prop('disabled', false);
                            }
                        });
                    });
                });
            </script>
            <?php
        } elseif ( 'shipping-sync' == $active_tab ) {
            ?>
            <hr>
            <h2><?php _e( 'Sync Shipping Data to WooCommerce', 'printumo-integration' ); ?></h2>
            <p><?php _e( 'This tool will automatically create or update WooCommerce Shipping Zones and Shipping Classes based on your Printumo shipping profiles.', 'printumo-integration' ); ?></p>
            <p><strong><?php _e( 'Important:', 'printumo-integration' ); ?></strong> <?php _e( 'This operation will modify your WooCommerce shipping settings. It will create new shipping zones and classes if they do not exist, and update existing ones with matching names/slugs. Existing shipping methods within zones will be updated with a base "Printumo Flat Rate" method.', 'printumo-integration' ); ?></p>
            <button id="printumo-sync-shipping-data" class="button button-primary"><?php _e( 'Sync Shipping Data to WooCommerce', 'printumo-integration' ); ?></button>
            <div id="printumo-sync-results" style="margin-top: 20px; background-color: #f0f0f0; padding: 15px; border-radius: 5px; max-height: 400px; overflow-y: auto; white-space: pre-wrap; word-wrap: break-word;">
                <?php _e( 'Sync results will appear here.', 'printumo-integration' ); ?>
            </div>

            <script type="text/javascript">
                jQuery(document).ready(function($) {
                    var wp_nonce = '<?php echo wp_create_nonce( 'wp_rest' ); ?>';

                    $('#printumo-sync-shipping-data').on('click', function() {
                        var $button = $(this);
                        var $resultsDiv = $('#printumo-sync-results');
                        $resultsDiv.text('<?php _e( 'Starting synchronization...', 'printumo-integration' ); ?>');
                        $button.prop('disabled', true);

                        $.ajax({
                            url: '<?php echo esc_url_raw( rest_url( 'printumo/v1/sync-shipping-data' ) ); ?>' + '?nonce=' + wp_nonce,
                            method: 'POST',
                            success: function(response) {
                                if (response.success) {
                                    $resultsDiv.text('<?php _e( 'Sync successful!', 'printumo-integration' ); ?>\n' + JSON.stringify(response.message, null, 2) + '\n' + JSON.stringify(response.details, null, 2));
                                } else {
                                    $resultsDiv.text('<?php _e( 'Sync failed!', 'printumo-integration' ); ?>\n' + JSON.stringify(response.message, null, 2) + '\n' + JSON.stringify(response.details, null, 2));
                                }
                            },
                            error: function(jqXHR, textStatus, errorThrown) {
                                var errorMessage = 'AJAX Error: ' + textStatus + ' - ' + errorThrown + '\n';
                                if (jqXHR.responseJSON && jqXHR.responseJSON.message) {
                                    errorMessage += 'Server Message: ' + jqXHR.responseJSON.message + '\n';
                                }
                                if (jqXHR.responseText) {
                                    errorMessage += 'Full Response: ' + jqXHR.responseText;
                                }
                                $resultsDiv.text(errorMessage);
                            },
                            complete: function() {
                                $button.prop('disabled', false);
                            }
                        });
                    });
                });
            </script>
            <?php
        } else { // 'error-log' tab
            printumo_display_error_log_table();
        }
        ?>
    </div>
    <?php
}

/**
 * Displays the error log table in the admin page.
 */
function printumo_display_error_log_table() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'printumo_error_logs';
    $per_page = 20; // Number of logs per page
    $current_page = isset( $_GET['paged'] ) ? max( 1, intval( $_GET['paged'] ) ) : 1;
    $offset = ( $current_page - 1 ) * $per_page;

    // Get total number of logs
    $total_logs = $wpdb->get_var( "SELECT COUNT(id) FROM $table_name" );

    // Get logs for the current page
    $logs = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT * FROM $table_name ORDER BY timestamp DESC LIMIT %d OFFSET %d",
            $per_page,
            $offset
        ),
        ARRAY_A
    );

    ?>
    <hr>
    <h2><?php _e( 'Printumo Error Log', 'printumo-integration' ); ?></h2>
    <p><?php _e( 'This table displays errors encountered during Printumo API interactions.', 'printumo-integration' ); ?></p>

    <?php if ( empty( $logs ) ) : ?>
        <p><?php _e( 'No errors logged yet.', 'printumo-integration' ); ?></p>
    <?php else : ?>
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th scope="col"><?php _e( 'ID', 'printumo-integration' ); ?></th>
                    <th scope="col"><?php _e( 'Timestamp', 'printumo-integration' ); ?></th>
                    <th scope="col"><?php _e( 'Type', 'printumo-integration' ); ?></th>
                    <th scope="col"><?php _e( 'Message', 'printumo-integration' ); ?></th>
                    <th scope="col"><?php _e( 'Details', 'printumo-integration' ); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ( $logs as $log ) : ?>
                    <tr>
                        <td><?php echo esc_html( $log['id'] ); ?></td>
                        <td><?php echo esc_html( $log['timestamp'] ); ?></td>
                        <td><?php echo esc_html( $log['type'] ); ?></td>
                        <td><?php echo esc_html( $log['message'] ); ?></td>
                        <td>
                            <?php
                            $details = json_decode( $log['details'], true );
                            if ( ! empty( $details ) ) {
                                echo '<pre style="max-height: 150px; overflow-y: auto; background-color: #fff; padding: 10px; border: 1px solid #ddd; border-radius: 3px;">' . esc_html( wp_json_encode( $details, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) ) . '</pre>';
                            } else {
                                echo '<em>' . esc_html__( 'No additional details.', 'printumo-integration' ) . '</em>';
                            }
                            ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <?php
        // Pagination
        $total_pages = ceil( $total_logs / $per_page );
        if ( $total_pages > 1 ) {
            echo '<div class="tablenav"><div class="tablenav-pages">';
            $page_links = paginate_links( array(
                'base'      => add_query_arg( 'paged', '%#%' ),
                'format'    => '',
                'prev_text' => '&laquo;',
                'next_text' => '&raquo;',
                'total'     => $total_pages,
                'current'   => $current_page,
                'add_args'  => array( 'tab' => 'error-log' ), // Keep the 'error-log' tab active
            ));
            echo $page_links;
            echo '</div></div>';
        }
        ?>
    <?php endif; ?>
    <?php
}


/**
 * Enqueues necessary scripts for the admin page.
 */
function printumo_enqueue_admin_scripts( $hook ) {
    if ( 'woocommerce_page_printumo-tools' !== $hook ) {
        return;
    }
    wp_enqueue_script( 'jquery' ); // jQuery is typically already enqueued in admin
}
add_action( 'admin_enqueue_scripts', 'printumo_enqueue_admin_scripts' );
