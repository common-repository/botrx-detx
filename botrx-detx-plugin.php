<?php
/**
 * Plugin Name: BotRx DeTx Plugin
 * Plugin URI: https://www.botrx.com/products/monitor/
 * Description: This is an BotRx DeTx Plugin that detects and IDs bad bots to reveal hidden threats.
 * Version: 1.0.7
 * Author: BotRx
 * Author URI: https://www.botrx.com/
 * License: GPL
 */

/**
 * tips:
 *   1. see debug log:
 * 
 *       tail -f /var/www/wordpress/wp-content/debug.log | grep botrx
 * 
 */

if (!defined("ABSPATH")) {
  exit; // Exit if accessed directly
}


// FIXME: some enviroment didn't support shmop_open... XD
$botrx_block_ddos_enable = false;
if ($botrx_block_ddos_enable) {
  require_once('block.php');
}


// ====================
// debug & logger
// ====================

$botrx_debug_file_individual = false; // output log to plugin folder
$botrx_debug_file = __DIR__.'/debug.log';
$botrx_debug_show_dbg = false; // false
$botrx_debug_show_trace = false; // false
$botrx_debug_show_timing = false;
$botrx_debug_show_ip = false;

function botrx_log_info($msg) {
  global $botrx_debug_file_individual;
  global $botrx_debug_file;
  if ($botrx_debug_file_individual) {
    $now = botrx_date_str(time(), true);
    error_log("[$now] [info] $msg".PHP_EOL, 3, $botrx_debug_file);
  } else {
    error_log("[info] $msg");
  }
}

function botrx_log_dbg($msg) {
  global $botrx_debug_file_individual;
  global $botrx_debug_file;
  global $botrx_debug_show_dbg;
  if ($botrx_debug_show_dbg) {
    if ($botrx_debug_file_individual) {
      $now = botrx_date_str(time(), true);
      error_log("[$now] [dbg]  $msg".PHP_EOL, 3, $botrx_debug_file);
    } else {
      error_log("[dbg] $msg");
    }
  }
}

function botrx_log_trace($msg) {
  global $botrx_debug_file_individual;
  global $botrx_debug_file;
  global $botrx_debug_show_trace;
  if ($botrx_debug_show_trace) {
    if ($botrx_debug_file_individual) {
      $now = botrx_date_str(time(), true);
      error_log("[$now] [trace]  $msg".PHP_EOL, 3, $botrx_debug_file);
    } else {
      error_log("[trace] $msg");
    }
  }
}

function botrx_date_str($time, $return_with_server_timezone) {
  if ($return_with_server_timezone) {
    $gmt_offset = get_option('gmt_offset');
    return date("Y/m/d H:i:s", $time + ($gmt_offset*3600));
  } else {
    return date("Y/m/d H:i:s", $time);
  }
}

function botrx_max_intval($val, $max) {
  $val = intval($val);
  if ($val > $max) {
    return $max;
  }
  return $val;
}

function botrx_getallheaders() {
    $headers = [];
    foreach ($_SERVER as $name => $value) {
      if (substr($name, 0, 5) == 'HTTP_') {
          $headers[str_replace(' ', '-', ucwords(strtoupper(str_replace('_', ' ', substr($name, 5)))))] = $value;
      }
    }
    return $headers;
}

function botrx_startsWith($string, $startString) {
  $length = strlen($startString);
  return (substr($string, 0, $length) === $startString);
}  

function botrx_endsWith($string, $endString) { 
$len = strlen($endString); 
if ($len == 0) { 
    return true; 
} 
return (substr($string, -$len) === $endString); 
} 

// ====================
// Main class
// ====================

class botRxPlugin {

  public static $botrx_version = '1.0.7';

  // ====================
  // servers
  // ====================
  private $cloud_server = 'https://data.eidolonsecurity.com';
  private $remote_ip = '';

  // ====================
  // settings
  // ====================
  private $block_ddos_header = "HTTP/1.1 403 Forbidden"; 
  private $block_ddos_threshold = 150; // 150 milliSeconds
  private $max_req_history = 10;
  private $max_req_time = 60 * 1000; // 60 sec

  private $advanced_mode = false;
  private $send_report_after_save = true;
  private $clear_data_after_send_report = true;

  private $debug_mode = false;
  private $debug_mode_show_variables = false;

  // ====================
  // wordpress option table
  // ====================
  private static $_table_name = 'botrx_stats';
  private $wp_options_table = 'botrx_setting';
  private $record;
  private $default_block_ddos = 0;
  private $default_intervals = 3;
  private $default_logo = 0; // false
  private $default_debug = 0; // false

  // ====================
  // my table
  // ====================
  private $table_name;
  private $stats;
  private $need_run = 0;

  // ====================
  // plugin activate
  // ====================

  public static function plugin_activate() {
    $botrx_version = botRxPlugin::$botrx_version;
    botrx_log_info("[botrx] activate... (version=$botrx_version)");
    botRxPlugin::botrx_upgrade_check();
    botRxPlugin::regist_rest_api();
  }

  public static function plugin_deactivate() {
    botrx_log_info('[botrx] deactivate...');
    // unscheduled
    $next_schedule = wp_next_scheduled('botrx_send_report');
    if ($next_schedule) {
      wp_unschedule_event($next_schedule,'botrx_send_report');
    }
  }

  public static function botrx_upgrade_check() {

    // stop create class when ajax (because they call static methods)
    if (botrx_startsWith($_SERVER['REQUEST_URI'], '/wp-admin/admin-ajax.php')) {
      return;
    }

    $botrx_version = botRxPlugin::$botrx_version;
    $db_version = get_option('botrx_version');
    $path = $_SERVER['REQUEST_URI'];
    botrx_log_dbg("[botrx_upgrade_check] db_version=$db_version, botrx_version=$botrx_version (trigger: $path)");

    // BY-166: update tables
    if (!empty($db_version)) {
      if ($db_version != $botrx_version) {
        botRxPlugin::botrx_upgrade_db($botrx_version, $db_version, botRxPlugin::get_table_name());
        update_option('botrx_version', $botrx_version);
      }
      return true;
    }

    // create tables
    botRxPlugin::create_table(botRxPlugin::get_table_name());
    update_option('botrx_version', $botrx_version);

    return false;
  }

  public static function plugin_uninstall() {
    botrx_log_info('[botrx] uninstall...');

    // drop table
    botRxPlugin::drop_table(botRxPlugin::get_table_name());
    delete_option('botrx_setting');
    delete_option('botrx_version');
  
    // unscheduled
    $next_schedule = wp_next_scheduled('botrx_send_report');
    if ($next_schedule) {
      wp_unschedule_event($next_schedule,'botrx_send_report');
    }
  }
  

  // ====================
  // construct
  // ====================

  public function __construct() {

    botRxPlugin::regist_rest_api();

    // stop create class when ajax (because they call static methods)
    if (botrx_startsWith($_SERVER['REQUEST_URI'], '/wp-admin/admin-ajax.php')) {
      return;
    }

    // global $wpdb;
    $this->table_name = botRxPlugin::get_table_name();
    $this->record = get_option($this->wp_options_table);

    // for debug !!
    if ($this->record) { // && $this->record['valid']
      $this->cloud_server = $this->record['cloud_server'];
    }

    // schedule
    add_filter('cron_schedules',  [$this, 'botrx_add_schedule_interval']); // add our interval
    // add_action('botrx_send_report', [$this, 'botrx_send_report_func']);
	  
    // FIXME: trigger schedule by myself
    if ($this->record) {
        $path = $_SERVER['REQUEST_URI'];
        $valid = $this->record['valid'];
        $next_schedule = wp_next_scheduled('botrx_send_report');

        if ($valid) {
        
          $this->need_run = false;
          if (!$next_schedule) {
            $this->need_run = true; // force create next_schedule when empty!!
          } else {
            $this->need_run = $next_schedule && time() >= $next_schedule;
          }
          $next_schedule_display = $next_schedule ? botrx_date_str($next_schedule, true) : 'no defined';
          botrx_log_trace("[botrx_init] valid=$valid, need_run=$this->need_run, next_schedule=($next_schedule_display), path=$path");

          if ($this->need_run) {
            // unschedule first
            if ($next_schedule) {
              wp_unschedule_event($next_schedule, 'botrx_send_report'); 
            }
            // run schedule by myself
            $this->botrx_send_report_func(); 
            // schedule next job
            $intervals = isset($this->record['intervals']) ? $this->record['intervals'] : $this->default_intervals;
            $this->botrx_set_schedule($intervals, true, false);
          } 
        }
    }
    
  }

  public static function get_table_name() {
    global $wpdb;
    return $wpdb->prefix.botRxPlugin::$_table_name;
  }

  public function botrx_get_export_filename() {
    $apiKey = $this->record['apiKey'];
    $export_filename = __DIR__.'/'.botRxPlugin::$_table_name.'_'.$apiKey.'.txt'; 
    return $export_filename;
 }

  // ====================
  // Normal user
  // ====================
  
  public function init_viewer() {
    $valid = $this->record['valid'];
    if (!$valid) {
      botrx_log_info("API Key is invalid, plaese config it first.");
      return;
    }

    // ignore .map file
    $domain = $this->get_domain();
    $path = $this->get_path();
    if (botrx_endsWith($path, '.map')) {
      // $_server_ = print_r($_SERVER, true);
      botrx_log_trace("[botrx_stats_new] ignore non HTML, path=$path");
      return;
    }

    // calculate avg_req_time
    global $botrx_block_ddos_enable;
    if ($botrx_block_ddos_enable) {
      $GLOBALS['avg_req_time'] = $avg_req_time = $this->botrx_avg_req_time();
      $attack_detect = $this->attack_detect($avg_req_time);
    } else {
      $GLOBALS['avg_req_time'] = $avg_req_time = 0;
      $attack_detect = '';
    }

    // get post data
    $botrx_version = botRxPlugin::$botrx_version;
    $post_id = $this->get_post_id();
    $title = empty($post_id) ? '' : get_the_title($post_id);
    
    $this->stats = [
      'version' => $botrx_version,
      'apiKey' => $this->record['apiKey'],
      'fp' => $this->get_dap_fp(),
      'dap_session_id' => $this->get_session_id(),
      'src_ip' => $this->get_remote_ip(),
      'server_ip' => $this->get_server_ip(),
      'domain' => $domain,
      'path' => $path,
      'query_string' => $this->get_query_string(),
      'title' => $title,
      'referer' => $this->get_referer($domain),
      'timestamp' => 0,
      'timestamp_out' => 0,
      // time
      'server_latency' => 0,
      'page_speed' => 0,
      'corejs_speed' => 0,
      'page_stay' => 0, // max=600000 (10 minutes)
      // servcie side check
      'avg_req_time' => $avg_req_time,
      'attack_detect' => $attack_detect,
      // others
      'user_agent' => $_SERVER['HTTP_USER_AGENT'],
      'outbound_resource' => '',
    ];

    // block the requests
    if ($botrx_block_ddos_enable && $this->record['block_ddos'] && $attack_detect) {
      $this->stats['timestamp'] = $this->get_timestamp();
      $this->save_stats();
      header($this->block_ddos_header);
      exit;
    }

    add_filter('script_loader_tag', [$this, 'handle_script_tag'], 10, 3 );

    add_action('wp_enqueue_scripts', [$this, 'add_client_logo']);
    add_action('wp_footer', [$this, 'add_client_debug_info']);

    add_action('login_enqueue_scripts', [$this, 'add_client_logo']); 
    add_action('login_footer', [$this, 'add_client_debug_info']);
  }

  public function botrx_avg_req_time() {
    global $botrx_block_ddos_enable;
    if (!$botrx_block_ddos_enable) {
      return 0;
    }

    // get history from shared memory
    $memory = new BotRxBlock();
    $history = $memory->read(); // request history
    if (!$history) {
      $history = "{}";
    }
    $history = json_decode($history, true);

    // append history
    $cache_key = $_SERVER['REMOTE_ADDR'];
    $cache_val = $this->get_timestamp(); // $_SERVER['REQUEST_URI'];
    if (!$history[$cache_key]) {
      $history[$cache_key] = [];
    }
    array_push($history[$cache_key], $cache_val);

    // check size
    if (count($history[$cache_key]) > $this->max_req_history) {
      array_shift($history[$cache_key]);
    }

    // calcuate avg time
    $avg_req_time = 0;
    $items = $history[$cache_key];
    $item_size = count($items);
    for ($i = $item_size-1; $i>=1; $i--) {
        $curr_val = $items[$i];
        $pre_val = $items[$i-1];
        $diff = $curr_val - $pre_val;
        if ($diff >= $this->max_req_time) { // avoid too large value
          $diff = $this->max_req_time;
        }
        $avg_req_time += $diff;
        // botrx_log_info("[history] $cache_key, $i, $diff");
    }
    $avg_req_time = intval($avg_req_time / $item_size);

    // if avg time too large, then limit it
    if ($avg_req_time >= $this->max_req_time) { 
      $avg_req_time = $this->max_req_time;
    }

    /* debug
    $shmid = $memory->shmid;
    botrx_log_dbg("[botrx_avg_req_time] shmid=$shmid, history=".print_r($history, true));
    */
    // botrx_log_info("[botrx_avg_req_time] $cache_key, avg_req_time=$avg_req_time");

    // save to shared memory
    $memory->write(json_encode($history));
    return $avg_req_time;
  }


  protected function attack_detect($avg_req_time) {

    global $botrx_block_ddos_enable;
    if (!$botrx_block_ddos_enable) {
      return '';
    }

    if ($avg_req_time > 0 && $avg_req_time <= $this->block_ddos_threshold) { 
      return 'DDoS'; // web_crawler
    }

    /* special case
    Acunetix-Product: WVS/12.0 (Acunetix Web Vulnerability Scanner - Free Edition)
    Acunetix-Scanning-agreement: Third Party Scanning PROHIBITED
    Acunetix-User-agreement: http://www.acunetix.com/wvs/disc.htm
    */
    $found = '';
    if (isset($_SERVER['HTTP_ACUNETIX_PRODUCT'])) {
      if (botrx_startsWith($_SERVER['HTTP_ACUNETIX_PRODUCT'], 'WVS/')) {
        $found = 'acunetix'; // bot_acunetix
      }
    }
    // if ($found) {
    //   botrx_log_info("[attack_detect] found = $found");
    // }
    return $found;
  }

  // protected function startsWith($string, $startString) {
  //     $length = strlen($startString);
  //     return (substr($string, 0, $length) === $startString);
  // }  

  // protected function endsWith($string, $endString) { 
  //   $len = strlen($endString); 
  //   if ($len == 0) { 
  //       return true; 
  //   } 
  //   return (substr($string, -$len) === $endString); 
  // } 

  protected function botrx_login(){
    botrx_log_info("[botrx_login]");
  }

  
  protected function get_remote_ip(){
    if (empty($this->remote_ip)) {

      $all_headers = botrx_getallheaders();
      $originating_ip_headers = array( 
        'CF-Connecting-IP', // (Cloudflare)
        'True-Client-IP', // (Cloudflare Enterprise plan)
        'Fastly-Client-IP', // (Fastly CND and Firebase hosting header)
        'True-Client-IP', //(Akamai and Cloudflare)
        'X-Real-IP', // (Nginx/FastCGI)
        'X-Cluster-Client-IP', // (Rackspace LB, Riverbed Stingray)
        'X-Client-IP',
        'X-Forwarded-For',
        'X-Forwarded',
        'REMOTE_ADDR'
      );

      $ip_addr = '';
      $ip_header = '';

      foreach ( $originating_ip_headers as $a_header ) {

        if (!empty($ip_addr)) {
          break;
        }

        // BY-79: get header value from $_SERVER & getallheaders
        $a_value = isset($_SERVER[ $a_header ]) ? $_SERVER[ $a_header ] : '';
        if (empty($a_value)) {
          if (isset( $all_headers[ $a_header ] ) ) {
            $a_value = $all_headers[ $a_header ];
          } else if (isset( $all_headers[ strtoupper($a_header) ] ) ) {
            $a_value = $all_headers[ strtoupper($a_header) ];
          }
        }
        
        if (!empty($a_value)) {
          foreach (explode(',',$a_value) as $a_ip ) {
            if (filter_var($a_ip, FILTER_VALIDATE_IP ) !== false) {
              $ip_header = $a_header;
              $ip_addr = $a_ip;
              break;
            }
          }
        }
      }

      global $botrx_debug_show_ip;
      if ($botrx_debug_show_ip) {
        botrx_log_dbg("[get_remote_ip] $ip_header = $ip_addr");
      }
      $this->remote_ip = $ip_addr;
    }

		return $this->remote_ip;
  }
  
  function add_client_logo() {
    $apiKey = $this->record['apiKey'];
    $valid = $this->record['valid'];
    $debug = $this->record['debug'];
    $logo = $this->record['logo'] == '0' ? 'none' : 'inline' ;
    $timestamp = $this->stats['timestamp'] = $this->get_timestamp();

    $ts = number_format($timestamp, 0, '.', '');
    $botrx_valid = $valid ? 'true' : 'false';
    // botrx_log_dbg('[add_client_logo] key='.$apiKey.', valid='.$valid.', timestamp='.$timestamp);
    
    // insert start time
    echo <<<EOF
      <script>
      var botrx_valid = $botrx_valid;
      var botrx_debug = $debug;
      var botrx_stats = {timestamp: $ts};
      </script>

EOF;

    // insert debug log
    global $botrx_debug_show_timing;
    if ($botrx_debug_show_timing) {
      echo <<<EOF
      <script>
      var botrx_timing_init = new Date().getTime(); // _diff = (botrx_timing_init-botrx_stats.timestamp)/1000;
      console.log('[botrx_timing] init')

      window.addEventListener("load", function() {
        console.log('[botrx_timing] load', getBotrxTimeDiff())
      })
      document.addEventListener("DOMContentLoaded", function(e) {
        console.log('[botrx_timing] readystatechange', getBotrxTimeDiff())
      })
      document.addEventListener("DOMContentLoaded", function() {
        console.log('[botrx_timing] DOMContentLoaded', getBotrxTimeDiff())
      })
      function getBotrxTimeDiff() {
        return new Date().getTime() - botrx_timing_init
      }
      </script>

EOF;
    }

    // insert corejs logo & script
    if ($valid) {
      /* catty: no use onload event for performance
      <img src="$this->cloud_server/build/byPass.jpg?apiKey=$apiKey" class="byPass-logo" style="display:$logo;position:fixed;left:0;bottom:0;opacity:.5;z-index:999;" onload="_lx=document.createElement('script');_lx.setAttribute('src',this.src.replace('.jpg','Loader.js'));document.body.appendChild(_lx)" />
      */
      $loader_js = "$this->cloud_server/build/byPassLoader.js?apiKey=$apiKey";
      echo <<<EOF
      <img src="$this->cloud_server/build/byPass.jpg?apiKey=$apiKey" class="byPass-logo" style="display:$logo;position:fixed;left:0;bottom:0;opacity:.5;z-index:999;"/>
      
EOF;
      // <script src="$this->cloud_server/build/byPassLoader.js?apiKey=$apiKey"></script>
      $this->add_client_script($loader_js);
    }

  }

  function add_client_script($loader_js) {
    wp_register_script('botrx_loader_js', $loader_js);
    wp_enqueue_script('botrx_loader_js');
    wp_enqueue_script(
        'botrx_ajax_script',
        plugins_url( '/botrx-detx-plugin.js', __FILE__ ),
        array(
          'botrx_loader_js', 
        'jquery')
    );

    $botrx_nonce = wp_create_nonce('botrx_nonce');
    wp_localize_script('botrx_ajax_script', 'botrx_ajax_obj', array(
        'ajax_url' => admin_url('admin-ajax.php'),
        'nonce'    => $botrx_nonce,
    ));
  }

 function handle_script_tag( $tag, $handle, $src ) {
    if ( $handle !== 'botrx_loader_js' ) {
      return $tag;
    }
    return "<script src='$src' async='async'></script>"; // BY-117: add 'async' to script tag for no block browser rendering
  }


  function save_stats() {
    $path = $_SERVER['REQUEST_URI'];
    $row_id = $this->stats['row_id'] = botRxPlugin::insert_row($this->stats, $this->table_name);
    $ip = $this->get_remote_ip();
    // $avg_req_time = $GLOBALS['avg_req_time'] || 0;
    botrx_log_info("[botrx_stats_new] row_id=$row_id, path=$path, ip=$ip");

  }

  function add_client_debug_info() {
    // save stats
    // $path = $_SERVER['REQUEST_URI'];
    // $row_id = $this->stats['row_id'] = botRxPlugin::insert_row($this->stats, $this->table_name);
    // $ip = $_SERVER['REMOTE_ADDR'];
    // $avg_req_time = $GLOBALS['avg_req_time'];
    // botrx_log_info("[botrx_stats_new] row_id=$row_id, path=$path, ip=$ip, avg_req_time=$avg_req_time");
    $this->save_stats();

    // output js
    $valid = $this->record['valid'];
    if ($valid) {
      $botrx_stats = base64_encode(json_encode($this->stats));
      ?>
        <script>
          Object.assign(botrx_stats, JSON.parse(window.atob("<?= $botrx_stats ?>")));
        </script>
      <?php
    }
  }

  
  public function get_timestamp() {
    return (float)(round(microtime(true) * 1000));
  }

  public static function get_timestamp2() { // FIXME:
    return (float)(round(microtime(true) * 1000));
  }

  public function get_server_ip() {
    $server_ip = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : '';
    return $server_ip;
  }

  public function get_domain() {
    $scheme = $_SERVER['REQUEST_SCHEME'];
    $domain = isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : '';
    $port = $_SERVER['SERVER_PORT'];
    if ($scheme == 'http' && $port == 80) {
      $port = '';
    } else if ($scheme == '' && $port == 80) {
      $scheme = 'http';
      $port = '';
    } else if ($scheme == 'https' && $port == 443) {
      $port = '';
    } else if ($scheme == '' && $port == 443) {
      $scheme = 'https';
      $port = '';
    } else {
      $port = ':'.$port;
    }
    $full_path = "{$scheme}://{$domain}{$port}";
    return $full_path;
  }

  public function get_path() {
    $path = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
    $idx = strpos($path, '?');
    if ($idx > -1) {
      $path = substr($path, 0, $idx);
    }
    return $path;
  }

  public function get_query_string() {
    $query_string = isset($_SERVER['QUERY_STRING']) ? urldecode($_SERVER['QUERY_STRING']) : '';
    return ($query_string);
  }

  public function get_referer($domain) {
    $referer = isset($_SERVER['HTTP_REFERER']) ? urldecode($_SERVER['HTTP_REFERER']) : '';
    return $referer;
  }


  public function get_post_id() {
    // FIXME: post_id have another format...XD

    $str = $_SERVER['QUERY_STRING'];
    $reg='/p=(\d+)/';
    preg_match($reg, $str, $result);

    $post_id = $result ? $result[1] : '';
    // botrx_log_dbg("[post_id] str=$str, post_id=$post_id");
    return $post_id;
    // return $result ? $result[1] : '';
  }

  public function get_session_id() {
    $cookies = isset($_SERVER['HTTP_COOKIE']) ? $_SERVER['HTTP_COOKIE'] : '';
    $reg='/dap_session_id=(.*?)(;|$)/';
    preg_match($reg, $cookies, $result);
    return $result ? $result[1] : '';
  }

  public function get_dap_fp() {
    $cookies = isset($_SERVER['HTTP_COOKIE']) ? $_SERVER['HTTP_COOKIE'] : '';
    $reg='/dap_fp=(.*?)(;|$)/';
    preg_match($reg, $cookies, $result);
    return $result ? $result[1] : '';
  }
  

  // ====================
  // Admin user
  // ====================

  // Add our WP admin hooks.
  public function init_admin() {
    add_action('admin_menu', [$this, 'add_menu']);
    add_action('admin_init', [$this, 'plugin_init']);

    if ($this->debug_mode) {
      $this->get_remote_ip();
    }
  }

  // Add our plugin's option page to the WP admin menu.
  public function add_menu() {
    // @see add_menu_page( $page_title, $menu_title, $capability, $menu_slug, $function, $icon_url, $position )
    add_menu_page(
      'BotRx', // $page_title
      'BotRx', // $menu_title
      'manage_options', // $capability
      'menu_botrx', //  $menu_slug,
      [$this, 'render_settings'], // $function
      plugin_dir_url( __FILE__ ) . '/icon.png'
    );
  }

  // Initialize our plugin's settings.
  public function plugin_init() {
    // @see register_setting($option_group, $option_name, $args)
    register_setting('botrx_group', $this->wp_options_table, [$this, 'save_callback']);

    // @see add_settings_section($id, $title, $callback, $page)
    add_settings_section(
      'botrx_section_setting',
      'General Setting',
      [$this, 'render_section_apiKey'],
      'botrx_page' // $page
    );

    // @see add_settings_field($id, $title, $callback, $page, $section, $args)
    add_settings_field(
      'botrx_apiKey',
      'API Key',
      [$this, 'render_field_apikey'],
      'botrx_page', // $page
      'botrx_section_setting' // $section,
    );

    
    // ====================
    // block_mode
    // ====================
    global $botrx_block_ddos_enable;
    if ($botrx_block_ddos_enable) {
      add_settings_section(
        'botrx_section_block',
        'Access control',
        '',
        'botrx_page' // $page
      );

      add_settings_field(
        'botrx_block',
        'DDoS',
        [$this, 'render_field_block'],
        'botrx_page',
        'botrx_section_block'
      );
    }
    
    // ====================
    // advanced_mode
    // ====================

    if ($this->advanced_mode || $this->debug_mode) {
      add_settings_section(
        'botrx_section_advanced',
        'Advanced Settings',
        '',
        'botrx_page' // $page
      );
    }
    
    if ($this->advanced_mode) {
      add_settings_field(
        'botrx_intervals',
        'Sync Interval',
        [$this, 'render_field_intervals'],
        'botrx_page',
        'botrx_section_advanced'
      );
   
      add_settings_field(
        'botrx_logo',
        'Logo display',
        [$this, 'render_field_logo'],
        'botrx_page',
        'botrx_section_advanced'
      );
    }

    // ====================
    // debug_mode
    // ====================
    if ($this->debug_mode) {
      add_settings_field(
        'botrx_debug',
        'Debug',
        [$this, 'render_debug'],
        'botrx_page',
        'botrx_section_advanced'
      );
      add_settings_field(
        'botrx_cloud_server',
        'Cloud Server',
        [$this, 'render_field_cloud_server'],
        'botrx_page',
        'botrx_section_advanced'
      );
    }

    add_settings_section(
      'botrx_section_scheduled',
      'Synchronize Information',
      [$this, 'render_schedule'],
      'botrx_page' // $page
    );
  }

  // ====================
  // render
  // ====================

  public function render_settings() {
    ?>
    <style>
      .botrx-valid, .blue {
        color: #0085ba;
        font-weight: bold;
      }
      .botrx-invalid {
        color: red;
        font-weight: bold;
      }
      .form-table th {
        white-space: nowrap;
      }
      .botrx_apikey {
        width: 400px;
      }
      .botrx_cloud_server {
        width: 300px;
      }
      select {
        min-width: 100px;
      }
      .render_schedule_info {
        font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;
        border-collapse: collapse;
        width: 100%;
        margin-top: 10px;
      }
      .render_schedule_info td, .render_schedule_info th {
        border: 1px solid #ddd;
        padding: 8px;
      }
      /* .render_schedule_info tr:nth-child(1){ */
      .render_schedule_info th {
        background-color: #4CAF50;
      }
      .botrx_debug_item {
        color: gray;
        white-space: pre;
      }
      .expire_interval {
        color: orange;
      }
    </style>
    <div class="wrap">
      <h1>BotRx > DeTx > Settings</h1>
      <form method="post" action="options.php">
        <?php
        settings_fields('botrx_group'); // $option_group
        do_settings_sections('botrx_page'); //$page
        submit_button();
        ?>
      </form>
    </div>
    <?php
  }
  
  public function render_section_apiKey() {
    // print 'Enter your API key below:<br>';
    print 'Request API Key from <a href="https://www.botrx.com/contact/">BotRx.com</a>, then enter it at below:<br>';
  }

  public function render_field_apikey() {
    printf(
      '<input type="text" id="key" name="%s[apiKey]" value="%s" maxlength="36" class="botrx_apikey" />',
      $this->wp_options_table,
      isset($this->record['apiKey']) ? esc_attr($this->record['apiKey']) : ''
    );

    $class = '';
    $status = '';
    $msg = 'is required';

    $valid = false;
    if (isset($this->record['valid'])) {
      $valid = $this->record['valid'];
      $class = $this->record['valid'] ? 'botrx-valid' : 'botrx-invalid';
      $status = $this->record['valid'] ? 'is valid' : 'is invalid !!';//esc_attr($this->record['status']);
    }

    printf(
      '&nbsp;<span class="description %s">%s</span>',
      $class,
      $status
    );

    // show syncStats button
    if ($valid && ($this->advanced_mode || $this->debug_mode)) {
    ?>
      <input type="submit" name="syncStats" id="syncStats" class="button button-secondary" style="display:none;margin-left:5px;" value="Sync Stats" title="Force sync stats to BotRx. (PS: only do it when wordpress schedule is not work correctly !!)">
      <script>
        jQuery(function() {
          jQuery('input[name=syncStats]').appendTo(jQuery('input[name=submit]').parent()).show()
        })
        </script>
    <?php
    }

  }

  public function render_field_cloud_server() {
    $cloud_server = isset($this->record['cloud_server']) ? esc_attr($this->record['cloud_server']) : $this->cloud_server;
    ?>  
        <input type="text" id="cloud_server" name="<?=$this->wp_options_table?>[cloud_server]" value="<?=$cloud_server?>" class="botrx_cloud_server" />
        <span>
          <== 
          <select id="cloud_server_options">
            <option value="" selected></option>
            <option value="https://data.eidolonsecurity.com">https://data.eidolonsecurity.com</option>
            <option value="https://demo.eidolonsecurity.com">https://demo.eidolonsecurity.com</option>
            <option value="https://10.15.0.49:9090">https://10.15.0.49:9090</option><!-- local test server -->
          </select>
          <script>
          jQuery('#cloud_server_options').change(function() {
            var val = jQuery(this).val()
            if (val) {
              jQuery('#cloud_server').val(jQuery(this).val())
            }
          })
          </script>
        </span>
   <?php
  }

  public function render_field_intervals() {
    $intervals = isset($this->record['intervals']) ? esc_attr($this->record['intervals']) : $this->default_intervals
    ?>
        <select name="<?= $this->wp_options_table ?>[intervals]" class="botrx_intervals">
          <option value="1" <?php selected($intervals, "1"); ?> >1</option>
          <option value="3" <?php selected($intervals, "3"); ?> >3</option>
          <option value="5" <?php selected($intervals, "5"); ?> >5</option>
          <option value="10" <?php selected($intervals, "10"); ?> >10</option>
        </select> minutes
   <?php
  }
  
  public function render_field_block() {
    $block_ddos = isset($this->record['block_ddos']) ? esc_attr($this->record['block_ddos']) : $this->default_block_ddos;
    ?>
        <select name="<?= $this->wp_options_table ?>[block_ddos]" class="botrx_block_ddos">
          <option value="1" <?php selected($block_ddos, "1"); ?> >Block</option>
          <option value="0" <?php selected($block_ddos, "0"); ?> >Monitor</option>
        </select>
        (block DDoS attack)
    <?php
  }

  public function render_field_logo() {
    $logo = isset($this->record['logo']) ? esc_attr($this->record['logo']) : $this->default_logo;
    ?>
        <select name="<?= $this->wp_options_table ?>[logo]" class="botrx_logo">
          <option value="0" <?php selected($logo, "0"); ?> >Hide</option>
          <option value="1" <?php selected($logo, "1"); ?> >Show</option>
        </select>
        (show/hide BotRx logo in page)
   <?php
  }

  public function render_debug() {
   $debug = isset($this->record['debug']) ? esc_attr($this->record['debug']) : $this->default_debug;
   ?>
        <select name="<?= $this->wp_options_table ?>[debug]" class="botrx_debug">
          <option value="0" <?php selected($debug, "0"); ?> >Off</option>
          <option value="1" <?php selected($debug, "1"); ?> >Server side</option>
          <option value="2" <?php selected($debug, "2"); ?> >Server + Client side</option>
        </select>
        (show/hide debug message)
   <?php
  }

  public function render_schedule() {
    $debug = isset($this->record['debug']) ? esc_attr($this->record['debug']) : $this->default_debug;

    global $wpdb;

    // Current_time
    $now = time();
    $now_utc = botrx_date_str($now, false);
    $now_local = botrx_date_str($now, true);
    $now_display = "UTC time is <b class=blue>$now_utc</b>. Local time is <b>$now_local</b>";

    // next schedule time
    $next_schedule = wp_next_scheduled('botrx_send_report') or '';
    $next_schedule_display = '';
    if ($next_schedule) {
      $next_schedule_utc = $next_schedule ? botrx_date_str($next_schedule, false) : '';
      $next_schedule_local = $next_schedule ? botrx_date_str($next_schedule, true) : '';
      $next_schedule_display = "UTC time is <b class=blue>$next_schedule_utc</b>. Local time is <b>$next_schedule_local</b>";
    }

    // get prev_sync_time from DB
    $prev_sync_time = $this->record['prev_sync_time'];
    $prev_sync_time_display = '';
    if (!empty($prev_sync_time)) {
      $prev_sync_count = $this->record['prev_sync_count'];
      $prev_sync_time = intval($prev_sync_time/1000); //  millisecond-> millisecond
      $prev_sync_time_utc = botrx_date_str($prev_sync_time, false);
      $prev_sync_time_local = botrx_date_str($prev_sync_time, true);

      // prev_sync_status(1=Connect fail, 2=API Key be disabled, 3=Success)
      $prev_sync_status = $this->record['prev_sync_status'];
      
      if ($prev_sync_status == 3 || empty($prev_sync_status)) {
        $prev_sync_time_display = "UTC time is <b>$prev_sync_time_utc</b>. Local time is <b>$prev_sync_time_local</b>. (Total is <b>$prev_sync_count</b> records)";
      } else {
        if ($prev_sync_status == 2) {
          $sprev_sync_msg = '(API Key be disabled)';
        } else { // status == 0
          $sprev_sync_msg = '(Cannot connect to BotRx server)';
        }
        $prev_sync_time_display = "UTC time is <b>$prev_sync_time_utc</b>. Local time is <b>$prev_sync_time_local</b>. <font color=red>$sprev_sync_msg</font>";
      }
    }

    // query db
    $botrx_table_stats = $wpdb->get_row('SELECT count(*) as table_count FROM '.$this->table_name, ARRAY_A);
    $botrx_table = $wpdb->get_results('SELECT * FROM '.$this->table_name.' ORDER BY id DESC LIMIT 50');

    // get display table
    $display = "(no data)";
    if ($botrx_table) {
      $display = "<table class='striped'><tr>";
      foreach ($botrx_table[0] as $att => $val) { // gen table header
        $display = $display."<td>$att</td>";
      }
      $display = $display."</tr>";
      foreach ($botrx_table as $name => $record) { // gen table data
        $display = $display."<tr>";
        foreach ($record as $att => $val) {
          if ($val== 0 && $att == 'timestamp_out') {
            $now = $this->get_timestamp();
            $expire_interval = intval(($now - $record->timestamp)/1000);
            $val = $val." <span class='expire_interval'>(stay $expire_interval sec)</span>";
          } else {
            $val = htmlspecialchars($val);
          }
          $display = $display."<td>$val</td>";
        }
        $display = $display."</tr>";
      }
      $display = $display."</table>";
    }
    
    printf('<table class="render_schedule_info" border="1">'); // print_r, var_dump
    printf('<tr><th>key</th><th>value</th></tr>');
    // $this->render_debug_item('Last_sync_file', $sync_file.$sync_file_exist);
    
    $this->render_debug_item('Current_time', $now_display);
    $this->render_debug_item('Prev_Sync_time', $prev_sync_time_display);
    $this->render_debug_item('Next_Sync_time', $next_schedule_display);
    // $this->render_debug_item('Need_Sync', '<b class=blue>'.($this->need_run?'true':'false').'</b>');

    if ($this->advanced_mode || $this->debug_mode) {
      $this->render_debug_item('Table_name', $this->table_name);
      $this->render_debug_item('Data_count', $botrx_table_stats['table_count']);
      $this->render_debug_item('Data', $display); // $botrx_table
    }

    if ($this->debug_mode_show_variables) {
      // $this->render_debug_item('headers_list', headers_list());
      // $this->render_debug_item('apache_request_headers', apache_request_headers());
      $this->render_debug_item('getallheaders', botrx_getallheaders());
      $this->render_debug_item('$_SERVER', $_SERVER);
    }

    printf('</table>');

  }

  public function render_debug_item($title, $item) {
    printf("<tr><td>$title</td>");
    printf("<td><div class='botrx_debug_item'>");
    print_r($item);
    printf("</div></td></tr>");
  }

  // ====================
  // schedule
  // ====================

  public function botrx_set_schedule($intervals, $force_update, $run_immediately) {
    $next_schedule = wp_next_scheduled('botrx_send_report');
    // botrx_log_dbg("[botrx_set_schedule][check] force_update=$force_update, run_immediately=$run_immediately, next_schedule=$next_schedule");

    if ($force_update || $run_immediately || !$next_schedule) {

      // remove old first
      if ($force_update || $run_immediately) {
        wp_unschedule_event($next_schedule, 'botrx_send_report');
      }

      // create new schedule
      $recurrence = 'botrx_'.$intervals.'_minutes';
      $nextRun = time();
      if (!$run_immediately) {
        $nextRun += ($intervals * 60);
      }
      $nextRun_display = botrx_date_str($nextRun, true);

      botrx_log_info("[botrx_set_schedule] intervals=$intervals, recurrence=$recurrence, force_update=$force_update, run_immediately=$run_immediately, next_schedule=($nextRun_display)");
      return wp_schedule_event($nextRun, $recurrence, 'botrx_send_report');
    }
    return false;
  }

  public function check_expire_sql($expire_interval) {
    global $wpdb;
    $table_name = botRxPlugin::get_table_name();
    $sql = "select
      UNIX_TIMESTAMP(), timestamp/1000, 
      (UNIX_TIMESTAMP()-(timestamp/1000)) as diff_second
    from $table_name
      where timestamp_out = 0
      having diff_second > $expire_interval";
    return $sql;
  }

  public function update_expire_sql($expire_interval) {
    global $wpdb;
    $table_name = botRxPlugin::get_table_name();
    /*
    $sql = "update $table_name
      set timestamp_out = UNIX_TIMESTAMP()*1000,
        page_stay = (UNIX_TIMESTAMP()-(timestamp/1000))*1000
    where timestamp_out = 0 
      and (UNIX_TIMESTAMP()-(timestamp/1000)) > $expire_interval";
    */
    $sql = "update $table_name
      set force_upload = 1
    where timestamp_out = 0 
      and (UNIX_TIMESTAMP()-(timestamp/1000)) > $expire_interval";
    return $sql;
  }

  public function botrx_send_report_func() {
    // botrx_log_dbg("[botrx_send_report_func][start]");

    // $self_path = $_SERVER['PHP_SELF'];
    $valid = $this->record['valid'];
    // botrx_log_dbg("[botrx_send_report_func][check] valid=$valid");

    if ($valid) {

      // define export file
      $apiKey = $this->record['apiKey'];
      $export_filename = $this->botrx_get_export_filename();
      

      global $wpdb;
      $table_name = botRxPlugin::get_table_name();

      // --------------------
      // check expire record
      // --------------------
      // update record which is expired (timestamp_out=0 && expired more than N minutes)
      $intervals = $this->record['intervals']; // sanitize_text_field($options['intervals']);
      $expire_interval = $intervals * 60; // N minutes
      $wpdb->query($this->update_expire_sql($expire_interval));

      // --------------------
      // query DB data
      // --------------------
      $query_sql = "SELECT * FROM $table_name WHERE timestamp_out != 0 OR force_upload = 1";
      $records = $wpdb->get_results($query_sql, ARRAY_A);
      $records_size = sizeof($records);
      // botrx_log_dbg("[botrx_send_report_func][check] records_size=$records_size");

      if ($records) {

        // export to file
        $export_file = fopen($export_filename, "w");
        foreach ($records as $record) {
          unset($record['id']);
          $record['timestamp'] = (float)$record['timestamp']; // string to bigint
          $record['timestamp_out'] = (float)$record['timestamp_out'];
          $record['server_latency'] = intval($record['server_latency']); // string to int
          $record['page_speed'] = intval($record['page_speed']);
          $record['corejs_speed'] = intval($record['corejs_speed']);
          $record['page_stay'] = botrx_max_intval($record['page_stay'], 600000);
          $record['force_upload'] = intval($record['force_upload']);
          $record['avg_req_time'] = intval($record['avg_req_time']);

          $txt = json_encode($record);
          fwrite($export_file, $txt."\n");
        }

        // sync report to cloud
        $sync_status = $this->botrx_send_report_to_cloud($apiKey, $export_filename);
        $this->record['prev_sync_status'] = $sync_status;
        $this->record['prev_sync_time'] = $this->get_timestamp();
        $this->record['prev_sync_count'] = 0;

        if ($sync_status > 1) {
          $this->record['prev_sync_count'] = sizeof($records);
          
          // clear table data
          if ($this->clear_data_after_send_report) {
            $this->botrx_clear_data($table_name);
          }
        }
        
        // save prev_sync_time in DB
        update_option($this->wp_options_table, $this->record);

        fclose($export_file);

      } else {
        botrx_log_info("[botrx_send_report_func] no data ");
      }

    } else {
      botrx_log_info("[botrx_send_report_func] apiKey is not valid");
    }
  }

  public function botrx_clear_data($table_name) {
    global $wpdb;
    /*
    $delete_sql = "DELETE FROM $table_name WHERE id <= $max_id";
    $wpdb->query($delete_sql);
    botrx_log_info("[botrx_clear_data] max_id=$max_id");
    */
    $delete_sql = "DELETE FROM $table_name WHERE timestamp_out != 0 OR force_upload = 1";
    $wpdb->query($delete_sql);
  }

  public function botrx_send_report_to_cloud($apiKey, $export_filename) {
    // $self_path = $_SERVER['PHP_SELF'];
    $url = esc_url_raw($this->cloud_server.'/bypass/serverModule/' . $apiKey . '/dataCollection') ;
    
    $post_fields = array(
      'name' => 'value',
    );
    $boundary = 'botrx-data-collection-boundary';// wp_generate_password(24);
    $headers  = array(
      'content-type' => 'multipart/form-data; boundary=' . $boundary,
    );
    $payload = '';
    // First, add the standard POST fields:
    foreach ( $post_fields as $name => $value ) {
      $payload .= '--' . $boundary;
      $payload .= "\r\n";
      $payload .= 'Content-Disposition: form-data; name="' . $name .
        '"' . "\r\n\r\n";
      $payload .= $value;
      $payload .= "\r\n";
    }
    // Upload the file
    if ( $export_filename ) {
      $payload .= '--' . $boundary;
      $payload .= "\r\n";
      $payload .= 'Content-Disposition: form-data; name="' . 'upload' .
        '"; filename="' . basename( $export_filename ) . '"' . "\r\n";
      //        $payload .= 'Content-Type: image/jpeg' . "\r\n";
      $payload .= "\r\n";
      $payload .= file_get_contents( $export_filename );
      $payload .= "\r\n";
    }
    $payload .= '--' . $boundary . '--';
    
    // POST
    $response = wp_remote_post($url, array(
      'timeout' => 5, 
      'sslverify'=> false,
      'headers'    => $headers,
      'body'       => $payload,
    ));
    $response_code = wp_remote_retrieve_response_code( $response );
    
    $valid = 1;

    if (is_wp_error($response)) {
      $error_code = $response->get_error_code();
      $error_message = $response->get_error_message();
      $error_data = $response->get_error_data($error_code);
      botrx_log_info('[botrx_send_report_func][err] ' .$url. ' ==> '. $error_code . ' ==> ' . $error_message . ' ==> ' . $error_data);
    } else {
      $body = $response['body'];
      if ($response_code == 200) {
        $valid = $body == 'true' ? 3 : 2;
      }
      botrx_log_info('[botrx_send_report_func]['.$response_code.'] ' .$url. ' ==> <' .gettype($body). '> "' . $body . '"');
      // botrx_log_dbg("headers = ".json_encode($headers));
      // botrx_log_dbg("payload = $payload");
    }

    return $valid;
  }

  public function botrx_add_schedule_interval($schedules) {
    $schedules['botrx_1_minutes'] = array(
      'interval' => 1 * 60,
      'display'  => esc_html__('Send report every 1 minute'),
    );
    $schedules['botrx_3_minutes'] = array(
      'interval' => 3 * 60,
      'display'  => esc_html__('Send report every 3 minutes'),
    );
    $schedules['botrx_5_minutes'] = array(
      'interval' => 5 * 60,
      'display'  => esc_html__('Send report every 5 minutes'),
    );
    $schedules['botrx_10_minutes'] = array(
      'interval' => 10 * 60,
      'display'  => esc_html__('Send report every 10 minutes'),
    );
    return $schedules;
  }

  
  // ====================
  // ajax
  // ====================

  public static function regist_rest_api() {
    // botrx_log_dbg("[regist_rest_api]");
    add_action('wp_ajax_botrx_stats_update', array('botRxPlugin', 'botrx_stats_update'));
    add_action('wp_ajax_nopriv_botrx_stats_update', array('botRxPlugin', 'botrx_stats_update'));
  }

  public static function botrx_stats_update() {
    // check token
    check_ajax_referer('botrx_nonce');

    // check record's id
    $path = $_SERVER['REQUEST_URI'];
    $row_id = isset($_POST['ri']) ? sanitize_text_field($_POST['ri']) : '';
    $valid_id = is_numeric($row_id);

    $leave_page = sanitize_text_field($_POST['lp']);
    $action_title = $leave_page ? '[botrx_stats_leave]' : '[botrx_stats_update]';
    // botrx_log_trace("$action_title row_id=$row_id, valid_id=$valid_id path=$path");

    if ($valid_id) {

      // get post data
      $dap_fp = sanitize_text_field(base64_decode($_POST['fp']));
      $dap_session_id = sanitize_text_field(base64_decode($_POST['si']));
      $timestamp_out = botRxPlugin::get_timestamp2(); // sanitize_text_field($_POST['ou']);
      $doc_title = sanitize_text_field(urldecode(base64_decode($_POST['tl'])));
      $outbound_resource = sanitize_text_field(base64_decode($_POST['or']));
      $server_latency = sanitize_text_field($_POST['sl']);
      $page_speed = sanitize_text_field($_POST['ps']);
      $corejs_speed = sanitize_text_field($_POST['cs']);
      $page_stay = sanitize_text_field($_POST['pt']);

      // query record
      global $wpdb;
      $table_name = botRxPlugin::get_table_name();
      $query_sql = "SELECT * FROM $table_name WHERE id = $row_id";
      $record = $wpdb->get_row($query_sql, ARRAY_A);
      $find = !empty($record);
      botrx_log_trace("$action_title row_id=$row_id, find=$find, leave_page=$leave_page, dap_session_id='$dap_session_id', server_latency=$server_latency, page_speed=$page_speed, corejs_speed=$corejs_speed, page_stay=$page_stay, timestamp_out=$timestamp_out, outbound_resource=$outbound_resource");

      // update record
      if ($find) {
        
        $record['fp'] = $dap_fp;

        /* FIXME: safari ITP issue
        if (empty($record['dap_session_id']) && !empty($dap_session_id)) { // only update when dap_session_id is empty (first request)
          $record['dap_session_id'] = $dap_session_id;


        }*/
        $record['dap_session_id'] = $dap_session_id;

        if (!empty($doc_title)) {
          $record['title'] = $doc_title;
        }
        if (!empty($outbound_resource)) {
          $record['outbound_resource'] = $outbound_resource;
        }
        if ($leave_page) {
          $record['timestamp_out'] = $timestamp_out;
          $record['page_stay'] = botrx_max_intval($page_stay, 600000);
        }
        $record['server_latency'] = $server_latency;
        $record['page_speed'] = $page_speed;
        $record['corejs_speed'] = $corejs_speed;
        botRxPlugin::update_row($record, $table_name);
        
        echo 'true'; 
      } else {
        echo 'false'; 
      }
    } else {
      botrx_log_trace("$action_title row_id is empty!!");
      echo 'false'; 
    }

    wp_die();
  }
  
  
  public function botrx_validate_apiKey($apiKey, $domain) {
    // FIXME: need check apiKey with domain !!
    $url = esc_url_raw($this->cloud_server.'/bypass/serverModule/' . $apiKey . '/verify') ;
    
    $response = wp_remote_get($url, array(
      'timeout' => 3, 
      'sslverify'=> false,
    ));
    $response_code = wp_remote_retrieve_response_code( $response );
    $valid = false;

    if (is_wp_error($response)) {
      $error_code = $response->get_error_code();
      $error_message = $response->get_error_message();
      $error_data = $response->get_error_data($error_code);
      botrx_log_info('[botrx_validate_apiKey][err] url=' .$url. ' ==> '. $error_code . ' ==> ' . $error_message . ' ==> ' . $error_data);
    } else {
      $body = $response['body'];
      if ($response_code == 200) {
        $valid = $body == 'true';
      }
      botrx_log_info('[botrx_validate_apiKey]['.$response_code.'] url=' .$url. ' ==> valid:'.($valid?'true':'false').' ==> <' .gettype($body). '> "' . $body . '"');
    }

    return $valid;
  }
  

  // ====================
  // DB
  // ====================

  public function save_callback($options) {
    $valid = true;

    if (!isset($options['apiKey']) or strlen($options['apiKey']) == 0) {
      add_settings_error($this->wp_options_table, esc_attr('settings_updated'), 'API Key is required', 'error');
      // return;
    }
    // botrx_log_info("[save_callback] options = ".json_encode($options));

    $domain = parse_url(get_bloginfo('url'), PHP_URL_HOST);
    $apiKey = sanitize_text_field($options['apiKey']);
    $cloud_server = isset($options['cloud_server']) ? sanitize_text_field($options['cloud_server']) : $this->cloud_server;
    $intervals = isset($options['intervals']) ? sanitize_text_field($options['intervals']) : $this->default_intervals;
    $logo = isset($options['logo']) ? sanitize_text_field($options['logo']) : $this->default_logo;
    $debug = isset($options['debug']) ? sanitize_text_field($options['debug']) : $this->default_debug;
    // botrx_log_info("[save_callback] cloud_server: '$cloud_server'");


    global $botrx_block_ddos_enable;
    $block_ddos = $this->default_block_ddos;
    if ($botrx_block_ddos_enable) {
      $block_ddos = isset($options['block_ddos']) ? sanitize_text_field($options['block_ddos']): $this->default_block_ddos;
    }

    $syncStats = empty($_REQUEST['syncStats']) ? '' : sanitize_text_field($_REQUEST['syncStats']);
    if (!empty($syncStats)) {
        $this->botrx_send_report_func();

    } else {
      // [Validate] cloud_server
      if (empty($cloud_server)) {
        $valid = false;
        add_settings_error($this->wp_options_table, esc_attr('settings_updated'), 'Cloud server is required', 'error');
      } else {
        $this->cloud_server = $cloud_server;
      }
      // [Validate] the apikey key within the scope of the current domain.
      if ($valid) {
        $valid = $this->botrx_validate_apiKey($apiKey, $domain);
      }

      if (!$valid) {
        add_settings_error($this->wp_options_table, esc_attr('settings_updated'), 'API Key is required', 'error');
        // return;
      }

      if ($valid) {
        $this->botrx_set_schedule($intervals, true, false); // $this->send_report_after_save);
      }
    }

    $cache = [
      'apiKey' => $apiKey,
      'valid' => $valid,
      'cloud_server' => isset($cloud_server) ? $cloud_server : $this->cloud_server,
      'intervals' => isset($intervals) ? $intervals : $this->default_intervals,
      'block_ddos' => isset($block_ddos) ? $block_ddos : $this->default_block_ddos,
      'logo' => isset($logo) ? $logo : $this->default_logo,
      'debug' => isset($debug) ? $debug : $this->default_debug,
      'prev_sync_count' => $this->record['prev_sync_count'],
      'prev_sync_time' => $this->record['prev_sync_time'],
      'prev_sync_status' => $this->record['prev_sync_status'],
    ];

    botrx_log_info("[save_callback] apiKey=$apiKey, valid=$valid, intervals=".$cache['intervals'].", logo=".$cache['logo'].", debug=".$cache['debug']);

    return $cache;
  }
  
  // insert new row(data)
  public static function insert_row( $_data = array(), $_table = '' ) {
		if ( empty( $_data ) || empty( $_table ) ) {
			return -1;
		}

		// Remove unwanted characters (SQL injections, anyone?)
		$data_keys = array();
		foreach ( array_keys( $_data ) as $a_key ) {
			$data_keys[] = sanitize_key( $a_key );
		}

    
    // prepare sql
    global $wpdb;
    $sql = "INSERT IGNORE INTO $_table (" . implode (", ", $data_keys) . ')
    VALUES (' . substr( str_repeat( '%s,', count( $_data ) ), 0, -1 ) . ")";

    // execute
		$wpdb->query( $wpdb->prepare($sql, $_data ) );
    $row_id = intval( $wpdb->insert_id );
    // botrx_log_dbg('[insert_row] row_id='.$row_id);
    // botrx_log_dbg('[insert_row] row_id='.$row_id.', sql='.$sql);

		return $row_id;
  }

  public static function update_row($_data = array(), $_table = ''){
		if (empty($_data) || empty($_table)){
			return -1;
		}

		// Move the ID at the end of the array
		$id = $_data['id'];
		unset($_data['id']);

		// Remove unwanted characters (SQL injections, anyone?)
		$data_keys = array();
		foreach (array_keys($_data) as $a_key){
			$data_keys[] = sanitize_key($a_key);
		}

		// Add the id at the end
		$_data['id'] = $id;

    // prepare sql
    global $wpdb;
    $sql = "UPDATE IGNORE $_table
    SET ".implode(' = %s, ', $data_keys)." = %s
    WHERE id = %d";
    // botrx_log_dbg('[update_row] sql='.$sql);

    // execute
		$wpdb->query($wpdb->prepare($sql, $_data));

		return 0;
	}
  
  public static function drop_table($table_name) {
    botrx_log_info('[botrx][drop_table] table_name='.$table_name);
    global $wpdb;
    $sql = "DROP TABLE IF EXISTS $table_name";
    $wpdb->query($sql);
  }

  // create tables
  public static function create_table($table_name) {
    // botrx_log_info("[botrx] create_table: $table_name");

    global $wpdb;
		$have_innodb = $wpdb->get_results( "SHOW VARIABLES LIKE 'have_innodb'", ARRAY_A ); // Is InnoDB available?
    $use_innodb = ( !empty( $have_innodb[ 0 ] ) && $have_innodb[ 0 ][ 'Value' ] == 'YES' ) ? 'ENGINE=InnoDB' : '';

    // PS: ip VARCHAR(45) --> IPv4-mapped IPv6 (45 characters)
    $table_stats_sql = "
        CREATE TABLE IF NOT EXISTS {$table_name} (
          id BIGINT UNSIGNED NOT NULL auto_increment,

          version VARCHAR(14) DEFAULT NULL,
          apiKey VARCHAR(36) DEFAULT NULL,
          fp VARCHAR(44) DEFAULT NULL,
          dap_session_id VARCHAR(14) DEFAULT NULL,
          src_ip VARCHAR(45) DEFAULT NULL,
          server_ip VARCHAR(45) DEFAULT NULL,
          domain VARCHAR(2048) DEFAULT NULL,
          path VARCHAR(2048) DEFAULT NULL,
          query_string VARCHAR(2048) DEFAULT NULL,
          title VARCHAR(2048) DEFAULT NULL,
          referer VARCHAR(2048) DEFAULT NULL,

          timestamp BIGINT UNSIGNED NOT NULL DEFAULT 0,
          timestamp_out BIGINT UNSIGNED NOT NULL DEFAULT 0,
          
          server_latency INT UNSIGNED NOT NULL DEFAULT 0,
          page_speed INT UNSIGNED NOT NULL DEFAULT 0,
          corejs_speed INT UNSIGNED NOT NULL DEFAULT 0,
          page_stay INT UNSIGNED NOT NULL DEFAULT 0,

          avg_req_time INT UNSIGNED NOT NULL DEFAULT 0,
          attack_detect VARCHAR(30) DEFAULT NULL,
          force_upload INT UNSIGNED NOT NULL DEFAULT 0,
          
          user_agent VARCHAR(2048) DEFAULT NULL,
          outbound_resource VARCHAR(2048) DEFAULT NULL,
        
          CONSTRAINT PRIMARY KEY (id)
        ) COLLATE utf8_general_ci $use_innodb";

    $table_exist = botRxPlugin::exec_table_sql($table_stats_sql, $table_name);
    botrx_log_info('[botrx][create_table] table_name='.$table_name.', table_exist='.$table_exist);
  }

  public static function botrx_upgrade_db($botrx_version, $db_version, $table_name) {    
    global $wpdb;

    // ====================
    // upgrade prcoess !!
    // ====================
    if ($botrx_version == '1.0.7') {
      // BY-166: fix some user synchronize statistics fail after upgrade (1.0.5 to 1.0.6).
      botrx_log_info("[botrx_upgrade_db] version=$botrx_version: recreate tables...");
      botRxPlugin::drop_table(botRxPlugin::get_table_name());
      botRxPlugin::create_table(botRxPlugin::get_table_name());

    } else if ($botrx_version == '1.0.6') {
      // BY-98: add column "version"
      botrx_log_info("[botrx_upgrade_db] version=$botrx_version: add new columns");
      $wpdb->query("ALTER TABLE $table_name ADD version VARCHAR(14) DEFAULT NULL;"); 
      $wpdb->query("ALTER TABLE $table_name ADD domain VARCHAR(2048) DEFAULT NULL;"); 
      $wpdb->query("ALTER TABLE $table_name ADD query_string VARCHAR(2048) DEFAULT NULL;"); 
      $wpdb->query("UPDATE $table_name SET version = '1.0.5' WHERE version is NULL;");
    }
  }

  public static function exec_table_sql($_sql = '', $table_name = '') {
    global $wpdb;
		$wpdb->query( $_sql );

    // check table is created
		foreach ( $wpdb->get_col( "SHOW TABLES LIKE '$table_name'", 0 ) as $a_table ) {
			if ( $a_table == $table_name ) {
				return true;
			}
		}

		return false;
  }

}

// ====================
// Init 
// ====================

register_activation_hook( __FILE__, array('botRxPlugin', 'plugin_activate'));
register_deactivation_hook( __FILE__, array('botRxPlugin', 'plugin_deactivate'));
register_uninstall_hook( __FILE__, array('botRxPlugin', 'plugin_uninstall'));


// BY-166:
// https://codex.wordpress.org/Creating_Tables_with_Plugins#Adding_an_Upgrade_Function
add_action('plugins_loaded', ['botRxPlugin', 'botrx_upgrade_check']);


$plugin = new botRxPlugin();
if (is_admin()) {
  $plugin->init_admin();
} else {
  $plugin->init_viewer();
}

// ====================
// test
// ====================

/*
function botrx_dump_request() {
  botrx_log_info("[admin-ajax] req=".json_encode($_REQUEST));
}

function botrx_dump_request_action() {
  $req_action = sanitize_text_field($_REQUEST['action']); // isset($_POST['action']) ? $_POST['action'] : '';
  $wp_action = "wp_ajax_{$req_action}";
  $flg = has_action($wp_action);
  botrx_log_info("[admin-ajax] req_action=$req_action, wp_action=$wp_action(exist=$flg), req=".json_encode($_REQUEST));
}
*/