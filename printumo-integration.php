<?php
/**
 * Plugin Name: Printumo Integration
 * Description: Handles WooCommerce order status changes to send orders to Printumo API, and provides tools to fetch Printumo data.
 * Version: 1.3.0
 * Author: Seu Nome
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
// CONFIGURAÇÕES BÁSICAS DA API (URLs)
// ====================================================================

// URL base da API da Printumo
define( 'PRINTUMO_BASE_API_URL', 'https://printumo.com/api/v1' );

// URL do endpoint de criação de pedidos da Printumo
define( 'PRINTUMO_ORDERS_API_URL', PRINTUMO_BASE_API_URL . '/orders' );

// URL do endpoint de produtos da Printumo
define( 'PRINTUMO_PRODUCTS_API_URL', PRINTUMO_BASE_API_URL . '/products' );

// URL do endpoint de perfis de envio da Printumo
define( 'PRINTUMO_SHIPPING_PROFILES_API_URL', PRINTUMO_BASE_API_URL . '/shipping_profiles' );

// ====================================================================
// ATIVAÇÃO DO PLUGIN - CRIAÇÃO DA TABELA DE LOGS DE ERRO
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
// FUNÇÃO PARA REGISTRAR ERROS NO BANCO DE DADOS
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
// REGISTRO DOS ENDPOINTS REST PARA OS WEBHOOKS E FERRAMENTAS
// ====================================================================

/**
 * Registers custom REST API endpoints for WooCommerce webhooks and Printumo data fetching.
 */
function printumo_register_api_endpoints() {
    // Endpoint para receber o webhook de atualização de status do pedido do WooCommerce
    register_rest_route( 'printumo/v1', '/webhook', array(
        'methods'             => 'POST',
        'callback'            => 'printumo_handle_webhook_data',
        // IMPORTANT: For production, implement robust permission_callback (e.g., shared secret verification).
        // For simplicity, we allow all requests here, but this is a security risk.
        'permission_callback' => '__return_true',
    ));

    // Endpoint para buscar produtos da Printumo (acionado via admin)
    register_rest_route( 'printumo/v1', '/fetch-products', array(
        'methods'             => 'GET',
        'callback'            => 'printumo_fetch_products_from_api',
        'permission_callback' => 'current_user_can', // Requires user to be logged in and have 'manage_options' capability
        'args'                => array(
            'nonce' => array(
                'validate_callback' => function( $param, $request, $key ) {
                    return wp_verify_nonce( $param, 'wp_rest' );
                },
                'required' => true,
            ),
        ),
    ));

    // Endpoint para buscar perfis de envio da Printumo (acionado via admin)
    register_rest_route( 'printumo/v1', '/fetch-shipping-profiles', array(
        'methods'             => 'GET',
        'callback'            => 'printumo_fetch_shipping_profiles_from_api',
        'permission_callback' => 'current_user_can', // Requires user to be logged in and have 'manage_options' capability
        'args'                => array(
            'nonce' => array(
                'validate_callback' => function( $param, $request, $key ) {
                    return wp_verify_nonce( $param, 'wp_rest' );
                },
                'required' => true,
            ),
        ),
    ));
}
add_action( 'rest_api_init', 'printumo_register_api_endpoints' );

// ====================================================================
// FUNÇÃO PARA LIDAR COM OS DADOS DO WEBHOOK (CRIAÇÃO DE PEDIDOS)
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
// FUNÇÕES PARA BUSCAR DADOS DA PRINTUMO (PRODUTOS E PERFIS DE ENVIO)
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
// FUNCIONALIDADES ADICIONAIS (OPCIONAIS, MAS ALTAMENTE RECOMENDADAS)
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
// PÁGINA DE ADMINISTRAÇÃO E CONFIGURAÇÕES DO PLUGIN
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
                    // Handle Fetch Products button click
                    $('#printumo-fetch-products').on('click', function() {
                        var $button = $(this);
                        var $resultsDiv = $('#printumo-products-results');
                        $resultsDiv.text('<?php _e( 'Fetching products...', 'printumo-integration' ); ?>');
                        $button.prop('disabled', true);

                        $.ajax({
                            url: '<?php echo esc_url_raw( rest_url( 'printumo/v1/fetch-products' ) ); ?>',
                            method: 'GET',
                            beforeSend: function(xhr) {
                                xhr.setRequestHeader('X-WP-Nonce', '<?php echo wp_create_nonce( 'wp_rest' ); ?>');
                            },
                            success: function(response) {
                                if (response.success) {
                                    $resultsDiv.text(JSON.stringify(response.data, null, 2));
                                } else {
                                    $resultsDiv.text('Error: ' + response.message);
                                }
                            },
                            error: function(jqXHR, textStatus, errorThrown) {
                                $resultsDiv.text('AJAX Error: ' + textStatus + ' - ' + errorThrown + ' - ' + (jqXHR.responseJSON ? jqXHR.responseJSON.message : ''));
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
                            url: '<?php echo esc_url_raw( rest_url( 'printumo/v1/fetch-shipping-profiles' ) ); ?>',
                            method: 'GET',
                            beforeSend: function(xhr) {
                                xhr.setRequestHeader('X-WP-Nonce', '<?php echo wp_create_nonce( 'wp_rest' ); ?>');
                            },
                            success: function(response) {
                                if (response.success) {
                                    $resultsDiv.text(JSON.stringify(response.data, null, 2));
                                } else {
                                    $resultsDiv.text('Error: ' + response.message);
                                }
                            },
                            error: function(jqXHR, textStatus, errorThrown) {
                                $resultsDiv.text('AJAX Error: ' + textStatus + ' - ' + errorThrown + ' - ' + (jqXHR.responseJSON ? jqXHR.responseJSON.message : ''));
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
